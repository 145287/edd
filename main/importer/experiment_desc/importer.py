# coding: utf-8
from __future__ import unicode_literals

import logging
import traceback

from collections import defaultdict, OrderedDict

import requests
from django.core.mail import mail_admins
from django.conf import settings
from django.core.urlresolvers import reverse
from django.db import transaction
from io import BytesIO

from openpyxl import load_workbook
from pprint import pformat

from requests.packages.urllib3 import HTTPResponse

from .constants import (
    FOUND_PART_NUMBER_DOESNT_MATCH_QUERY,
    NON_STRAIN_ICE_ENTRY,
    PART_NUMBER_NOT_FOUND, BAD_REQUEST, INTERNAL_SERVER_ERROR, UNPROCESSABLE, OK, FORBIDDEN,
    FORBIDDEN_PART_KEY, GENERIC_ICE_RELATED_ERROR, IGNORE_ICE_RELATED_ERRORS_PARAM,
    ALLOW_DUPLICATE_NAMES_PARAM, NOT_FOUND)
from .parsers import ExperimentDescFileParser, JsonInputParser
from .utilities import (CombinatorialCreationPerformance, find_existing_strains)
from jbei.rest.auth import HmacAuth
from jbei.rest.clients import IceApi
from jbei.rest.clients.ice.api import Strain as IceStrain, VERIFY_SSL_DEFAULT, DEFAULT_RESULT_LIMIT, \
    ICE_URL
from jbei.rest.clients.ice.utils import make_entry_url
from main.models import Protocol, MetadataType, Strain, Assay, Line


logger = logging.getLogger(__name__)

ERRORS_KEY = 'errors'
WARNINGS_KEY = 'warnings'
_IGNORE_ICE_RELATED_ERRORS_DEFAULT = False

_ALLOW_DUPLICATE_NAMES_DEFAULT = False
_DRY_RUN_DEFAULT = False


# for safety / for now get repeatable reads within this method, even though writes start much later
# possibility of long-running transactions as a result, but should be infrequent
@transaction.atomic(savepoint=False)
def define_study(stream, user, study, is_json,
                 allow_duplicate_names=_ALLOW_DUPLICATE_NAMES_DEFAULT, dry_run=_DRY_RUN_DEFAULT,
                 ignore_ice_errors=_IGNORE_ICE_RELATED_ERRORS_DEFAULT):
    # TODO: relocate to a Celery task and add related user notifications/context-appropriate
    # error handling following initial testing/deployment.
    # This function's parameters are structured in a similar form to the Celery task, though
    # initial testing / UI work should be easier to test with it executing synchronously. Unlikely
    # that very large inputs will be provided often, so asynchronous processing is desirable
    # here, but not required for the anticipated majority of use cases.

    """
    Defines a study from the set of lines / assays provided in the template file parameter. Study
    lines / assays, and are all created atomically, so any failure
    prevents  changes from taking hold.  Known sources of error are exhaustively checked and
    summarized in JSON output, even in the event of failure. Any strains
    specified in the input file, and not already
    present in EDD's local cache of ICE strains, will be automatically added iff they can be
    uniquely identified in ICE. Several caveats are:
    1) Line names must be unique within the study, or the creation task will be aborted.

    Note that this method performs work very similar to EDD's bulk line creation script,
    create_lines.py.
    :return: A JSON summary string if lines/assays were created successfully,
    raises an Exception otherwise
    """
    importer = CombinatorialCreationImporter(study, user)
    return importer.do_import(stream, is_json, allow_duplicate_names, dry_run,
                              ignore_ice_related_errors=ignore_ice_errors)


def _build_response_content(errors, warnings, val=None):
    """
    Builds a dictionary of response content that summarizes processing performed by the
    experiment description attempt, including any errors or warnings that occurred along the way.
    :param errors: a dictionary of errors that maps one of the known keys to a list of values
    associated with that error (e.g. ICE part IDs)
    :param warnings: a dictionary of warnings that maps one of the known keys to a list of values
    associated with that warning (e.g. ICE part IDs)
    :param val: the existing dictionary to add errors and warnings to, or if None, a new one
    will be created.
    :return: the dictionary containing errors and warnings
    """
    if val is None:
        val = {}
    if errors:
        val[ERRORS_KEY] = errors
    if warnings:
        val[WARNINGS_KEY] = warnings
    return val


class CombinatorialCreationImporter(object):
    REQUIRE_STRAINS = True

    def __init__(self, study, user):

        self.performance = CombinatorialCreationPerformance()
        self.errors = defaultdict(list)
        self.warnings = defaultdict(list)
        self._input_summary = None

        self.exception_interrupted_ice_queries = False

        ###########################################################################################
        # Gather context from EDD's database
        ###########################################################################################

        # TODO: these should be queried separately when this code gets relocated to a Celery task
        self.user = user
        self.study = study

        # build up a dictionary of protocols with unique names (guaranteed by Protocol.save())
        protocols_qs = Protocol.objects.all()
        self.protocols_by_pk = {protocol.pk: protocol for protocol in protocols_qs}

        # build up dictionaries of Line and Assay metadata types with unique names (guaranteed by
        # DB constraints) TODO: I18N
        line_metadata_qs = MetadataType.objects.filter(for_context=MetadataType.LINE)
        self.line_metadata_types_by_pk = {
            meta_type.pk: meta_type
            for meta_type in line_metadata_qs
        }
        # TODO: I18N
        assay_metadata_qs = MetadataType.objects.filter(for_context=MetadataType.ASSAY)

        self.assay_metadata_types_by_pk = {
            meta_type.pk: meta_type
            for meta_type in assay_metadata_qs
        }
        self.performance.end_context_queries()

    @property
    def _ice_username(self):
        if self.user:
            return self.user.email
        return None

    def add_issue(self, is_error, type, value):
        if is_error:
            self.add_error(type, value)
        else:
            self.add_warning(type, value)

    def add_error(self, error_type, error_value):
        self.errors[error_type].append(error_value)

    def add_warning(self, warning_type, warning_value):
        self.warnings[warning_type].append(warning_value)

    def do_import(self, request, is_json, allow_duplicate_names=_ALLOW_DUPLICATE_NAMES_DEFAULT,
                  dry_run=_DRY_RUN_DEFAULT,
                  ignore_ice_related_errors=_IGNORE_ICE_RELATED_ERRORS_DEFAULT):
        """
        Performs the import or raises an Exception if an unexpected / unhandled error occurred

        :return: a json dict with a summary of import results (for success or failure)
        """

        ############################################################################################
        # Clear out state from previous import attempts using this importer
        ############################################################################################
        self.performance.reset()
        self._input_summary = None
        self.errors.clear()
        self.warnings.clear()
        self.exception_interrupted_ice_queries = False

        ###########################################################################################
        # Parse / validate the input against metadata defined in the database
        ###########################################################################################
        # Note: it would be more memory efficient to perform creation after reading each line of
        # the file, but that's not likely to be a problem. Can do that optimization later after
        # enforcing a good separation of concerns with this general layout.
        protocols_by_pk = self.protocols_by_pk
        line_metadata_types_by_pk = self.line_metadata_types_by_pk
        assay_metadata_types_by_pk = self.assay_metadata_types_by_pk

        # parse the input contents (should be relatively short since they're likely manual input)
        if is_json:
            parser = JsonInputParser(protocols_by_pk, line_metadata_types_by_pk,
                                     assay_metadata_types_by_pk,
                                     require_strains=self.REQUIRE_STRAINS)
            self._input_summary = request # cache for possible inclusion in error emails
            input_data = request
        else:
            input_data = load_workbook(BytesIO(request.read()), read_only=True, data_only=True)
            if len(input_data.worksheets) == 0:
                self.add_error('no_input', 'no worksheets in file')

            parser = ExperimentDescFileParser(protocols_by_pk, line_metadata_types_by_pk,
                                              assay_metadata_types_by_pk,
                                              require_strains=self.REQUIRE_STRAINS)

        line_def_inputs = parser.parse(input_data, self)
        self.performance.end_input_parse()

        if not line_def_inputs:
            self.add_error('no_inputs', 'No line description inputs were read')

        # if there were any file parse errors, return helpful output before attempting any
        # database insertions. Note: returning normally causes the transaction to commit, but that
        # is ok here since no DB changes have occurred yet
        if self.errors:
            return BAD_REQUEST, _build_response_content(self.errors, self.warnings)

        # cache a human-readable summary of input for possible use in error emails
        if is_json:
            self._input_summary = parser.parsed_json
        else:
            self._input_summary = request.META.get('HTTP_X_FILE_NAME')

        with transaction.atomic(savepoint=False):
            return self._define_study(
                combinatorial_inputs=line_def_inputs,
                allow_duplicate_names=allow_duplicate_names,
                dry_run=dry_run,
                ignore_ice_related_errors=ignore_ice_related_errors,
            )

    def _define_study(self, combinatorial_inputs,
                      allow_duplicate_names=_ALLOW_DUPLICATE_NAMES_DEFAULT,
                      dry_run=_DRY_RUN_DEFAULT,
                      ignore_ice_related_errors=_IGNORE_ICE_RELATED_ERRORS_DEFAULT):
        """
        Queries EDD and ICE to verify that the required ICE strains have an entry in EDD's
        database. If not, creates them.  Once strains are created, combinatorially creates lines
        and assays within the study as specified by combinatorial_inputs.
        :return: A JSON summary string that summarizes results of the attempted line/assay/strain
            creation
        :raise Exception: if an unexpected error occurs.
        """

        # get some convenient references to unclutter syntax below
        line_metadata_types = self.line_metadata_types_by_pk
        assay_metadata_types = self.assay_metadata_types_by_pk
        performance = self.performance
        user = self.user
        study = self.study

        # TODO: to support JSON with possible mixed known/unknown strains for the combinatorial
        # GUI, test whether input resulted from JSON, then skip initial part number lookup for
        # anything that is an integer (assuming it's a local pk for a known strain).
        # Maybe there's a better solution?

        ###########################################################################################
        # Search ICE for entries corresponding to the part numbers in the file
        ###########################################################################################

        # build a list of unique part numbers found in the input file. we'll query ICE to get
        # references to them. Note: ideally we'd do this externally to the @atomic block, but other
        # EDD queries have to precede this one
        # TODO: restore keeping part numbers in the order found for readability in user messages
        unique_part_numbers = set()
        ice_parts_by_number = OrderedDict()

        for combo in combinatorial_inputs:
            unique_part_numbers = combo.get_unique_strain_ids(unique_part_numbers)

        # maps part id -> Entry for those found in ICE
        unique_part_number_count = len(unique_part_numbers)

        # query ICE for UUID's part numbers found in the input file
        # NOTE: important to preserve EDD's ability to function without ICE here, so we need some
        # nontrivial error handling to handle ICE/communication errors while still informing the
        # user about problems that occurred / gaps in data entry
        try:
            self.get_ice_entries(unique_part_numbers, ice_parts_by_number,
                                 ignore_ice_related_errors=ignore_ice_related_errors)

        # handle uncaught errors as a result of ICE communication (e.g.
        # requests.ConnectionErrors that we purposefully avoid catching above since they likely
        # impact all future requests)
        except IOError as err:
            self._handle_systemic_ice_error(ignore_ice_related_errors,
                                            unique_part_numbers, ice_parts_by_number)
        performance.end_ice_search(len(ice_parts_by_number), unique_part_number_count)

        # if we've detected one or more systemic ICE-related errors during individual queries for
        # part ID's, send a single error email to admins that aggregates them as determined by
        # error handling in get_ice_entries()
        if self.errors:
            self._notify_admins_of_systemic_ice_related_errors(ignore_ice_related_errors,
                                                               allow_duplicate_names, unique_part_numbers,
                                                               ice_parts_by_number)

            status_code = (NOT_FOUND if self.errors.get(PART_NUMBER_NOT_FOUND, False)
                           else INTERNAL_SERVER_ERROR)
            return status_code, _build_response_content(self.errors, self.warnings)
        elif GENERIC_ICE_RELATED_ERROR in self.warnings:
            self._notify_admins_of_systemic_ice_related_errors(ignore_ice_related_errors,
                                                               allow_duplicate_names,
                                                               unique_part_numbers,
                                                               ice_parts_by_number)

        ###########################################################################################
        # Search EDD for existing strains using UUID's queried from ICE
        ###########################################################################################

        # query EDD for Strains by UUID's found in ICE
        strain_search_count = len(ice_parts_by_number)
        edd_strains_by_part_number, non_existent_edd_strains = (
            find_existing_strains(ice_parts_by_number, self))
        performance.end_edd_strain_search(strain_search_count)

        ###########################################################################################
        # Create any missing strains in EDD's database.
        # Even if this is a dry run, we'll go ahead with caching since it's likely to be used below
        # or referenced again soon.
        ###########################################################################################
        self.create_missing_strains(non_existent_edd_strains, edd_strains_by_part_number)
        strains_by_pk = {strain.pk: strain for strain in edd_strains_by_part_number.itervalues()}
        performance.end_edd_strain_creation(len(non_existent_edd_strains))

        ###########################################################################################
        # Replace part-number-based strain references in the input with local primary keys usable
        # to create Line entries in EDD's database
        ###########################################################################################
        for input_set in combinatorial_inputs:
            input_set.replace_strain_part_numbers_with_pks(edd_strains_by_part_number,
                                                           ice_parts_by_number)

        ###########################################################################################
        # Compute line/assay names if needed as output for a dry run, or if needed to proactively
        # check for duplicates
        ###########################################################################################
        # For maintenance: Note that line names may contain strain information that has to be
        # looked up above before the name can be determined
        planned_names = []
        if dry_run or (not allow_duplicate_names):
            planned_names = self._compute_and_check_names(combinatorial_inputs, strains_by_pk,
                                                          allow_duplicate_names)
            performance.end_naming_check()

        # return just the planned line/assay names if we're doing a dry run
        if dry_run:
            content = {
                'planned_results': planned_names
            }
            _build_response_content(self.errors, self.warnings, val=content)

            status = 200
            if self.errors and not allow_duplicate_names:
                status = UNPROCESSABLE

            return status, content

        # if we've detected errors before modifying the study, fail before attempting db mods
        if self.errors:
            return UNPROCESSABLE, _build_response_content(self.errors, self.warnings)

        ###########################################################################################
        # Create requested lines and assays in the study
        ###########################################################################################
        created_lines_list = []
        total_assay_count = 0
        for input_set in combinatorial_inputs:

            creation_visitor = input_set.populate_study(
                study,
                line_metadata_types=line_metadata_types,
                assay_metadata_types=assay_metadata_types,
                strains_by_pk=strains_by_pk
            )
            created_lines_list.extend(creation_visitor.lines_created)
            items = creation_visitor.line_to_protocols_to_assays_list.iteritems()
            for line_pk, protocol_to_assays_list in items:
                for protocol, assays_list in protocol_to_assays_list.iteritems():
                    total_assay_count += len(assays_list)

        ###########################################################################################
        # Package up and return results
        ###########################################################################################
        total_line_count = len(created_lines_list)
        performance.overall_end()

        if self.errors:
            raise RuntimeError('Errors occurred during experiment description upload')

        logger.info('Created %(line_count)d lines and %(assay_count)d assays in %(seconds)0.2f '
                    'seconds' % {
                        'line_count': total_line_count,
                        'assay_count': total_assay_count,
                        'seconds': performance.total_time_delta.total_seconds(), })

        content = {
            'lines_created': total_line_count,
            'assays_created': total_assay_count,
            'runtime_seconds': performance.total_time_delta.total_seconds()
        }

        return OK, _build_response_content(self.errors, self.warnings, content)

    def _compute_and_check_names(self, combinatorial_inputs, strains_by_pk, allow_duplicate_names):
        """
        Tests the input for non-unique line/assay naming prior to attempting to insert it into the
        database, then captures errors if any duplicate names would be created during database I/O.
        Testing for inconsistency first should be efficient in may error cases, where it prevents
        unnecessary database I/O for line/assay creation prior to detecting duplicated naming.
        :return a dict with a hierarchical listing of all planned line/assay names (regardless of
        whether some are duplicates)
        """
        logger.info('in determine_names()')

        # get convenient references to unclutter syntax below
        line_metadata_types = self.line_metadata_types_by_pk
        assay_metadata_types = self.assay_metadata_types_by_pk
        study = self.study

        # Check for uniqueness of planned names so that overlaps can be flagged as an error (e.g.
        # as possible in the combinatorial GUI mockup attached to EDD-257)
        unique_input_line_names = set()
        protocol_to_unique_input_assay_names = defaultdict(dict)
        duplicated_new_line_names = set()
        protocol_to_duplicate_new_assay_names = defaultdict(list)

        # line name -> protocol -> [assay name], across all combinatorial inputs.
        all_planned_names = defaultdict(lambda: defaultdict(list))

        # loop over the sets of combinatorial inputs, computing names of new lines/assays to be
        # added to the study, and checking for any potential overlap in the input line/assay names.
        # This step doesn't required any database I/O, so we'll do it first to check for
        # self-inconsistent input. While we're at it, merge results from all sets of combinatorial
        # inputs to build a superset of planned results.

        # Note that we're creating two similar dicts here for different purposes:
        # protocol_to_unique_input_assay_names detects assay name uniqueness across all
        # CombinatorialInputDescriptions for a single protocol.  All_planned_names is the union of
        # all the planned names for each CombinatorialDescriptionInput (regardless of uniqueness).
        for input_set in combinatorial_inputs:
            names = input_set.compute_line_and_assay_names(study, line_metadata_types,
                                                           assay_metadata_types, strains_by_pk)
            for line_name in names.line_names:
                protocol_to_assay_names = names.line_to_protocols_to_assays_list.get(line_name)

                if line_name in unique_input_line_names:
                    duplicated_new_line_names.add(line_name)
                else:
                    unique_input_line_names.add(line_name)

                # defaultdict, so side effect is assignment
                all_protocol_to_assay_names = all_planned_names[line_name]

                for protocol_pk, assay_names in protocol_to_assay_names.items():
                    all_planned_assay_names = all_protocol_to_assay_names[protocol_pk]

                    for assay_name in assay_names:
                        all_planned_assay_names.append(assay_names)

                        unique_assay_names = protocol_to_unique_input_assay_names[protocol_pk]

                        if assay_name in unique_assay_names.keys():
                            duplicate_names = protocol_to_duplicate_new_assay_names[protocol_pk]
                            duplicate_names.append(assay_name)
                        else:
                            unique_assay_names[assay_name] = True

        # if we're allowing duplicate names, skip further checking / DB queries for duplicates
        if allow_duplicate_names:
            return all_planned_names

        # return early if the input isn't self-consistent
        for dupe in duplicated_new_line_names:
            self.add_error('duplicate_input_line_names', dupe)

        for dupe in protocol_to_duplicate_new_assay_names:
            self.add_error('duplicate_input_assay_names', dupe)

        if duplicated_new_line_names or protocol_to_duplicate_new_assay_names:
            return all_planned_names

        # query the database in bulk for any existing lines in the study whose names are the same
        # as lines in the input
        unique_line_names_list = list(unique_input_line_names)
        existing_lines = Line.objects.filter(study__pk=study.pk, name__in=unique_line_names_list)

        for existing in {line.name for line in existing_lines}:
            self.add_error('existing_line_names', existing)

        # do a series of bulk queries to check for uniqueness of assay names within each protocol
        for protocol_pk, assay_names_list in protocol_to_unique_input_assay_names.iteritems():
            existing_assays = Assay.objects.filter(
                name__in=assay_names_list,
                line__study__pk=study.pk,
                protocol__pk=protocol_pk
            )
            for existing in {assay.name for assay in existing_assays}:
                self.add_error('existing_assay_names', existing)

        return all_planned_names

    def create_missing_strains(self, non_existent_edd_strains, edd_strains_by_part_number):
        """
        Creates Strain entries from the associated ICE entries for any parts.

        :param non_existent_edd_strains: a list of ICE entries to use as the basis for EDD
            strain creation
        :return:
        """
        # just do it in a loop. EDD's Strain uses multi-table inheritance, which prevents bulk
        # creation
        for ice_entry in non_existent_edd_strains:
            # for now, only allow strain creation in EDD -- non-strains are not currently
            # supported. see EDD-239.
            if not isinstance(ice_entry, IceStrain):
                self.add_error(NON_STRAIN_ICE_ENTRY, ice_entry.part_id)
                continue
            strain = Strain.objects.create(
                name=ice_entry.name,
                description=ice_entry.short_description,
                registry_id=ice_entry.uuid,
                registry_url=make_entry_url(settings.ICE_URL, ice_entry.id)
            )
            edd_strains_by_part_number[ice_entry.part_id] = strain

    def get_ice_entries(self, part_numbers, part_number_to_part,
                        ignore_ice_related_errors=_IGNORE_ICE_RELATED_ERRORS_DEFAULT):
        """
        Queries ICE for parts with the provided (locally-unique) numbers, logging errors for any
        parts that weren't found into the errors parameter. Note that we're purposefully trading
        off readability for a guarantee of multi-deployment uniqueness, though as in use at JBEI
        the odds are still pretty good that a part number is sufficient to uniquely identify an ICE
        entry.

        :param part_numbers: a dictionary whose keys are part numbers to be queried
            from ICE. Existing entries will be replaced with the Entries read from ICE, or keys
            will be removed for those that aren't found in ICE.
        """

        # get an ICE connection to look up strain UUID's from part number user input
        ice = IceApi(auth=HmacAuth(key_id=settings.ICE_KEY_ID, username=self._ice_username),
                     verify_ssl_cert=settings.VERIFY_ICE_CERT)

        list_position = 0

        # treat inability to locate an individual part as an error if globally configured to ignore
        # missing strains, or if specifically requested for on this attempt
        treat_as_error = not ignore_ice_related_errors

        for local_ice_part_number in part_numbers:
            # query ICE for this part
            found_entry = None
            try:
                found_entry = ice.get_entry(local_ice_part_number)

            # catch only HTTPErrors, which are likely to apply only to a single ICE entry.
            # Note that ConnectionErrors and similar that are more likely to be systemic aren't
            # caught here and will immediately abort the remaining ICE queries.
            except requests.exceptions.HTTPError as http_err:
                # Track errors, while providing special-case error handling/labeling for ICE
                # permissions errors that are useful to detect on multiple parts in one attempt.
                # Note that depending on the error type, there may not be a response code (e.g.
                # transient 500 errors observed on edd-test/registry-test.jbei.org)
                response_status = http_err.response.status if hasattr(http_err.response,
                                                                      'status') else 'Unknown'

                # if error reflects a condition likely to repeat for each entry,
                # or that isn't useful to know individually per entry, abort the remaining queries.
                # Note this test only covers the error conditions known to be produced by
                # ICE, not all the possible HTTP error codes we could handle more explicitly. Also
                # note that 404 is handled above in get_entry().
                if response_status != FORBIDDEN:
                    self._handle_systemic_ice_error(ignore_ice_related_errors,
                                                    part_numbers, part_number_to_part)
                    return

                # aggregate errors that are helpful to detect on a per-part basis
                self.add_issue(treat_as_error, FORBIDDEN_PART_KEY, local_ice_part_number)

            if found_entry:
                part_number_to_part[local_ice_part_number] = found_entry
                # double-check for a coding error that occurred during testing. initial test parts
                # had "JBX_*" part numbers that matched their numeric ID, but this isn't always the
                # case!
                if found_entry.part_id != local_ice_part_number:
                    logger.error(
                        "Couldn't locate ICE entry \"%(csv_part_number)s\" "
                        "(#%(list_position)d in the file) by part number. An ICE entry was "
                        "found with numeric ID %(numeric_id)s, but its part number "
                        "(%(part_number)s) didn't match the search part number" % {
                            'csv_part_number': local_ice_part_number,
                            'list_position': list_position, 'numeric_id': found_entry.id,
                            'part_number': found_entry.part_id
                        })
                    self.add_error(FOUND_PART_NUMBER_DOESNT_MATCH_QUERY, found_entry.part_id)

            else:
                # collect the full set of missing strains rather than failing after the first
                self.add_issue(treat_as_error, PART_NUMBER_NOT_FOUND, local_ice_part_number)

    def _handle_systemic_ice_error(self, ignore_ice_related_errors, part_numbers, ice_entries):
        """
        Builds a helpful user-space error / warning message, then caches it
        :param err:
        :param ignore_ice_related_errors:
        :param part_number_count:
        :param ice_entries:
        :param ice_username:
        :return:
        """
        logger.exception('Error querying ICE for part number(s)')

        self.exception_interrupted_ice_queries = True
        base_message = ("ICE couldn't be contacted to find strains referenced in your "
                        "file, and EDD administrators have been notified of the problem.")

        # If not specifically-requested by the UI, the normal case should be to reject the upload
        # and force the user to acknowledge / override the problem rather than silently working
        # around it. In this unlikely case,
        # this approach is slightly more work for  users, but also allows them to prevent
        # creating inconsistencies that they'll have  to resolve later using more
        # labor-intensive processes (e.g. potentially expensive manual line edits).
        if not ignore_ice_related_errors:
            self.add_error(GENERIC_ICE_RELATED_ERROR,
                           "%(base_message)s\n\n You can try again later, or proceed now and omit "
                           "strain data from new lines in your study. If you omit strain "
                           "data now, you'll have to manually edit your lines later after the "
                           "problem is fixed.  Depending on the experiment, manually filling in "
                           "the missing strain data later could be more work. \n\n"
                           "Do you want to proceed without including the strains you used?" % {
                               'base_message': base_message})

        # If user got feedback re: ICE communication errors and chose to proceed anyway,
        # build a descriptive warning message re: the error, then proceed with line/assay
        # creation
        else:

            # build a nice warning message that summarizes the state of the study following
            # creation
            found_entries_count = len(ice_entries)
            unique_part_number_count = len(part_numbers)
            if found_entries_count:
                percent_found = float(len(ice_entries)) / unique_part_number_count
                warn_msg = ("%(base_message)s\n\n Lines were added to your study, but some won't "
                            "be associated with ICE strains. %(found)d of %(total)d "
                            "unique strains (%(percent)0.2f) were found before the error "
                            "occurred. The rest will need to be added later after the problem is "
                            "fixed." % {
                                'base_message': base_message, 'found': found_entries_count,
                                'total': unique_part_number_count, 'percent': percent_found,
                            })
            else:
                warn_msg = ('No lines created in this study could be associated with ICE '
                            'strains.')
            self.add_warning(GENERIC_ICE_RELATED_ERROR, warn_msg)

    def _notify_admins_of_systemic_ice_related_errors(self, ignore_ice_related_errors,
                                                      allow_duplicate_names, unique_part_numbers,
                                                      ice_parts_by_number):
        """
        If configured, builds and sends a time-saving notification email re: ICE communication
        problems to EDD admins. The email informs admins of problems that should be resolved without
        user involvement, and aggregates/captures relevant context that will be hard to remember
        and extract from log content and complex related code.
        """

        # even though users may be able to work around the error, email EDD admins since they
        # should look into / resolve systemic ICE communication errors without user
        # intervention. Since communication via the Internet is involved, possible that the
        # errors during a workaround are different than during the first attempt. We'll clearly
        # mark that case in the email subject, but still send the email.

        if (GENERIC_ICE_RELATED_ERROR not in self.errors and GENERIC_ICE_RELATED_ERROR not in
                self.warnings):
            return

        subject = 'ICE-related error during Experiment Description%s' % (
                   ': (User Ignored)' if ignore_ice_related_errors else '')

        # build traceback string to include in the email
        formatted_lines = traceback.format_exc().splitlines()
        traceback_str = '\n'.join(formatted_lines)

        part_numbers_not_found = [part_number for part_number in unique_part_numbers if
                                  part_number not in ice_parts_by_number]
        not_found_part_count = len(part_numbers_not_found)
        desired_part_count = len(unique_part_numbers)
        not_found_part_percent = 100 * ((float(not_found_part_count) / desired_part_count)
                                 if desired_part_count else 0)

        message = ('One or more error(s) occurred when attempting to add Experiment '
                   'Description data for EDD study %(study_pk)d:\n\n'
                   '\tStudy URL: %(study_pk)s\n'
                   '\tUsername: %(ice_username)s\n'
                   '\tRelevant request parameters:\n'
                   '\t\t%(ignore_ice_errors_param)s: %(ignore_ice_errors_val)s\n'
                   '\t\t%(allow_duplicate_names_param)s: %(allow_duplicate_names_val)s\n'
                   '\tUnique part numbers (%(unique_part_number_count)d): '
                   '%(unique_part_numbers)s\n'
                   '\tParts not found in ICE (%(not_found_part_count)d or '
                   '%(not_found_percent)0.2f%%): '
                   '%(parts_not_found)s\n'
                   '\tErrors detected during Experiment Description processing (may not '
                   'include the error below, if there\'s a traceback): %(errors)s\n\n'
                   '\tWarnings detected during Experiment Description processing:\n'
                   '\t %(warnings)s\n\n'
                   '\tUser input source: %(user_input_source)s\n\n'
                   'The contents of the most-recent full traceback was:\n\n'
                   '%(traceback)s' % {
                            'study_pk': self.study.pk,
                            'study_url': reverse('main:overview_by_pk',
                                                 kwargs={'pk': self.study.pk}),
                            'ice_username': self._ice_username,
                            'ignore_ice_errors_param': IGNORE_ICE_RELATED_ERRORS_PARAM,
                            'allow_duplicate_names_val': allow_duplicate_names,
                            'ignore_ice_errors': str(ignore_ice_related_errors),
                            'ignore_ice_errors_val': ignore_ice_related_errors,
                            'allow_duplicate_names_param': ALLOW_DUPLICATE_NAMES_PARAM,
                            'not_found_part_count': not_found_part_count,
                            'parts_not_found': str(part_numbers_not_found),
                            'not_found_percent': not_found_part_percent,
                            'unique_part_number_count': desired_part_count,
                            'unique_part_numbers': str(unique_part_numbers),
                            'errors': pformat(str(self.errors)),
                            'warnings': pformat(str(self.warnings)),
                            'user_input_source': pformat(str(self._input_summary)),
                            'traceback': traceback_str,
                        })

        mail_admins(subject=subject, message=message, fail_silently=True)


class IceTestStub(IceApi):

    def __init__(self, auth, base_url=ICE_URL, result_limit=DEFAULT_RESULT_LIMIT,
                 verify_ssl_cert=VERIFY_SSL_DEFAULT):
        super(IceTestStub, self).__init__(auth, base_url=base_url, result_limit=result_limit,
                                          verify_ssl_cert=verify_ssl_cert)

        self._query_num = 0
        self._fail_on_query_num = 2  # set to nonzero to test failure/partial success!

    """
    A variant of IceAPI that captures important test conditions for Experiment Description ICE
    queries and allows us to quickly do basic testing without having CI yet / putting more effort
    into automated tests. Note: code here is very simple, but actually took a while to find,
    since there as so many similarly named classes/options in requests, Django, etc that aren't
    well-documented.  This code is worth keeping until replaced with an automated test.
    """

    def get_entry(self, entry_id, suppress_errors=False):
        self._query_num += 1

        # if configured, work normally, deferring failure until the requested query #
        if self._query_num != self._fail_on_query_num:
            logger.debug('On query %d ...waiting to fail on #%d..' % (
                self._query_num, self._fail_on_query_num))
            return super(IceTestStub, self).get_entry(entry_id, suppress_errors=suppress_errors)

        # NOTE: all tests below assume the first-run case where ignore_ice_related_errors=False.
        # All the expected results still hold if it's False, except the response should always be
        #  200 (success)

        ############################################################################################
        # Test condition 1:
        ############################################################################################
        # Uncomment this block to test connection errors.
        #
        # Expected results to verify (manually for now):
        #    A) admin email sent (probably via an added log message...not working in DEV ATM)
        #    B) generic user-facing error message about ICE-related problems
        #    C) 500 "internal server error" response (use Chrome's "network" develop tool)
        ############################################################################################
        # raise requests.exceptions.ConnectionError()

        ############################################################################################
        # Test condition 2:
        ############################################################################################
        # Uncomment this block to test bad user data entry for part IDs
        #
        # Expected results to verify (manually for now):
        #    A) *NO* admin email sent (probably via an added log message...not working in DEV ATM)
        #    B) User error message lists parts that couldn't be found
        #    C) 404 "not found" response (use Chrome's "network" develop tool)
        ############################################################################################
        # return None

        ############################################################################################
        # Test conditions 3-4:
        ############################################################################################
        # uncomment a single status code and the bottom code block in this
        # method to test various supported error responses from ICE.
        #
        # Expected results to verify (manually for now):
        #    A) Admin email sent (probably via an added log message...not working in DEV ATM)
        #    B) User error message mentions generic ICE-related problems
        #    C) 500 "internal server error" response (use Chrome's "network" develop tool)

        # Condition 3
        # message = 'Bad client request'
        # status = BAD_REQUEST

        # Condition 4
        # message = 'Internal Server Error'
        # status = INTERNAL_SERVER_ERROR

        ############################################################################################
        # Test condition 5:
        ############################################################################################
        # Uncomment a  status code and the bottom code block in this
        # method to test various supported error responses from ICE.
        #
        # Expected results to verify (manually for now):
        #    A) *NO* Admin email sent (probably via an added log message...not working in DEV ATM)
        #    B) User error message specifically mentions ICE permission problems
        #    C) 403 "forbidden" response (use Chrome's "network" develop tool)
        message = 'Forbidden'
        status = FORBIDDEN

        ############################################################################################
        # Supporting error-generation code for test conditions 3-5 above
        ############################################################################################
        from requests import HTTPError
        response = HTTPResponse(status=status)
        error = HTTPError(message, response=response)
        raise error

