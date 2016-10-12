# coding: utf-8
from __future__ import unicode_literals

import logging

from builtins import str
from collections import OrderedDict
from django.db.models import Prefetch, Q
from django.utils.translation import ugettext_lazy as _


logger = logging.getLogger(__name__)


class ColumnChoice(object):
    def __init__(self, model, key, label, lookup, heading=None, lookup_kwargs={}):
        self._model = model
        self._key = '.'.join([model.__name__, key, ]) if model else key
        self._label = label
        self._lookup = lookup
        self._heading = heading if heading is not None else label
        self._lookup_kwargs = lookup_kwargs

    @classmethod
    def coerce(cls, instances):
        lookup = {col.get_key(): col for col in instances}
        return lambda key: lookup.get(key, None)

    def convert_instance_from_measure(self, measure, default=None):
        from main.models import Assay, Line, Measurement, Protocol, Study
        try:
            return {
                Assay: measure.assay,
                Line: measure.assay.line,
                Measurement: measure,
                Protocol: measure.assay.protocol,
                Study: measure.assay.line.study,
            }.get(self._model, default)
        except AttributeError:
            return default

    def convert_instance_from_line(self, line, protocol, default=None):
        from main.models import Line, Protocol, Study
        try:
            return {
                Line: line,
                Protocol: protocol or default,
                Study: line.study,
                None: line,
            }.get(self._model, default)
        except AttributeError:
            return default

    def get_field_choice(self):
        return (self._key, self._label)

    def get_heading(self):
        return self._heading

    def get_key(self):
        return self._key

    def get_value(self, instance, **kwargs):
        try:
            lookup_kwargs = {}
            lookup_kwargs.update(**self._lookup_kwargs)
            lookup_kwargs.update(**kwargs)
            return self._lookup(instance, **lookup_kwargs)
        except Exception as e:
            logger.exception('Failed to get column value: %s', e)
            return ''


class EmptyChoice(ColumnChoice):
    """ Always inserts an empty value on lookup callback. """
    def __init__(self):
        super(EmptyChoice, self).__init__(str, '', '', lambda x: '')


class ExportSelection(object):
    """ Object used for selecting objects for export. """
    def __init__(self, user, studyId=[], lineId=[], assayId=[], measureId=[]):
        # cannot import these at top-level
        from main.models import Assay, CarbonSource, Line, Measurement, Strain, Study
        # check studies linked to incoming IDs for permissions
        matched_study = Study.objects.filter(
            Q(pk__in=studyId, active=True) |
            Q(line__in=lineId, line__active=True) |
            Q(line__assay__in=assayId, line__assay__active=True) |
            Q(line__assay__measurement__in=measureId, line__assay__measurement__active=True)
        ).distinct(
        ).prefetch_related(
            'userpermission_set',
            'grouppermission_set',
        )
        self._allowed_study = [s for s in matched_study if s.user_can_read(user)]
        # load all matching measurements
        self._measures = Measurement.objects.filter(
            # all measurements are from visible study
            Q(assay__line__study__in=self._allowed_study),
            # OR grouping finds measurements under one of passed-in parameters
            Q(assay__line__study__in=studyId) |
            Q(assay__line__in=lineId, assay__line__active=True) |
            Q(assay__in=assayId, assay__active=True) |
            Q(pk__in=measureId, active=True),
        ).order_by(
            'assay__protocol_id'
        ).select_related(
            'measurement_type',
            'x_units',
            'y_units',
            'update_ref__mod_by',
            'experimenter',
            'assay__experimenter',
            'assay__protocol',
            'assay__line__contact',
            'assay__line__experimenter',
            'assay__line__study',
        )
        self._assays = Assay.objects.filter(
            Q(line__study__in=self._allowed_study),
            Q(line__in=lineId, line__active=True) |
            Q(pk__in=assayId, active=True) |
            Q(measurement__in=measureId, measurement__active=True),
        ).distinct(
        ).select_related(
            'protocol',
        )
        self._lines = Line.objects.filter(
            Q(study__in=self._allowed_study),
            Q(study__in=studyId) |
            Q(pk__in=lineId, active=True) |
            Q(assay__in=assayId, assay__active=True) |
            Q(assay__measurement__in=measureId, assay__measurement__active=True),
        ).distinct(
        ).select_related(
            'experimenter__userprofile', 'updated',
        ).prefetch_related(
            Prefetch('strains', queryset=Strain.objects.order_by('id')),
            Prefetch('carbon_source', queryset=CarbonSource.objects.order_by('id')),
        )

    @property
    def studies(self):
        """ List of studies allowed to be viewed in the selection. """
        return self._allowed_study

    @property
    def study_columns(self):
        from main.models import Study
        return Study.export_columns(self.studies)

    @property
    def lines(self):
        """ A queryset of lines included in the selection. """
        return self._lines

    @property
    def line_columns(self):
        from main.models import Line
        return Line.export_columns(self.lines)

    @property
    def assays(self):
        """ A queryset of assays included in the selection. """
        return self._assays

    @property
    def assay_columns(self):
        from main.models import Assay
        return Assay.export_columns(self.assays)

    @property
    def measurements(self):
        """ A queryset of measurements to include. """
        # TODO: add in empty measurements for assays that have none
        return self._measures

    @property
    def measurements_list(self):
        if not hasattr(self, '_measures_list'):
            self._measures_list = list(self._measures)
        return self._measures_list


class ExportOption(object):
    """ Object used for options on a table export. """
    DATA_COLUMN_BY_LINE = 'dbyl'
    DATA_COLUMN_BY_POINT = 'dbyp'
    LINE_COLUMN_BY_DATA = 'lbyd'
    LAYOUT_CHOICE = (
        (DATA_COLUMN_BY_LINE, _('columns of metadata types, and rows of lines/assays')),
        (DATA_COLUMN_BY_POINT, _('columns of metadata types, and rows of single points')),
        (LINE_COLUMN_BY_DATA, _('columns of lines/assays, and rows of metadata types')),
    )
    COMMA_SEPARATED = ','
    COMMA_SEPARATED_TOKEN = ','
    TAB_SEPARATED = '\t'
    TAB_SEPARATED_TOKEN = '\\t'
    # need to choose value tokens that can be displayed as HTML
    SEPARATOR_CHOICE = (
        (COMMA_SEPARATED_TOKEN, _('Comma-separated (CSV)')),
        (TAB_SEPARATED_TOKEN, _('Tab-separated')),
    )
    SEPARATOR_LOOKUP = {
        COMMA_SEPARATED_TOKEN: COMMA_SEPARATED,
        TAB_SEPARATED_TOKEN: TAB_SEPARATED,
    }
    ALL_DATA = 'all'
    SUMMARY_DATA = 'summary'
    NONE_DATA = 'none'
    FORMAT_CHOICE = (
        (ALL_DATA, _('All')),
        (SUMMARY_DATA, _('Summarize')),
        (NONE_DATA, _('None')),
    )

    def __init__(self, layout=DATA_COLUMN_BY_LINE, separator=COMMA_SEPARATED, data_format=ALL_DATA,
                 line_section=False, protocol_section=False, columns=[], blank_columns=[],
                 blank_mod=0):
        self.layout = layout
        self.separator = separator
        self.data_format = data_format
        self.line_section = line_section
        self.protocol_section = protocol_section
        self.columns = columns
        self.blank_columns = blank_columns
        self.blank_mod = blank_mod

    @classmethod
    def coerce_separator(cls, value):
        return cls.SEPARATOR_LOOKUP.get(value, cls.COMMA_SEPARATED)


def value_str(value):
    """ used to format value lists to a colon-delimited (unicode) string """
    # cast to float to remove 0-padding
    return ':'.join(map(str, map(float, value)))


class TableExport(object):
    """ Outputs tables for export of EDD objects. """
    def __init__(self, selection, options, worklist=None):
        self.selection = selection
        self.options = options
        self.worklist = worklist
        self._x_values = {}

    def output(self):
        """ Builds the CSV of the table export output. """
        # store tables; protocol PK keys table for measurements under a protocol, 'line' keys table
        #   for line-only section (if enabled), 'all' keys table including everything.
        tables = OrderedDict()
        if self.options.line_section:
            tables['line'] = OrderedDict()
            tables['line']['header'] = self._output_line_header()
        if not self.options.protocol_section:
            tables['all'] = OrderedDict()
            tables['all']['header'] = self._output_header()
        self._do_export(tables)
        return self._build_output(tables)

    def _build_output(self, tables):
        layout = self.options.layout
        table_separator = '\n\n'
        row_separator = '\n'
        cell_separator = self.options.separator
        if layout == ExportOption.DATA_COLUMN_BY_POINT:
            # data is already in correct orientation, join and return
            return table_separator.join([
                row_separator.join([
                    cell_separator.join([
                        str(cell) for cell in rrow
                        ]) for rkey, rrow in ttable.items()
                    ]) for tkey, ttable in tables.items()
                ])
        # both LINE_COLUMN_BY_DATA and DATA_COLUMN_BY_LINE are constructed similarly
        # each table in LINE_COLUMN_BY_DATA is transposed
        out = []
        for tkey, table in tables.items():
            # sort x values by original numeric values
            all_x = sorted(self._x_values.get(tkey, {}).items(), key=lambda a: a[1])
            # generate header row
            rows = [map(str, table['header'] + map(lambda x: x[0], all_x))]
            # go through non-header rows; unsquash final column
            for rkey, row in table.items()[1:]:
                unsquash = self._output_unsquash(all_x, row[-1:][0])
                rows.append(map(str, row[:-1] + unsquash))
            # do the transpose here if needed
            if layout == ExportOption.LINE_COLUMN_BY_DATA:
                rows = zip(*rows)
            # join the cells
            rows = [cell_separator.join(row) for row in rows]
            # join the rows
            out.append(row_separator.join(rows))
        return table_separator.join(out)

    def _do_export(self, tables):
        from main.models import Assay, Line, Measurement, MeasurementValue, Protocol, Study
        # add data from each exported measurement; already sorted by protocol
        measures = self.selection.measurements.prefetch_related(
            Prefetch('measurementvalue_set', queryset=MeasurementValue.objects.order_by('x')),
            Prefetch('assay__line__strains'),
            Prefetch('assay__line__carbon_source'),
        )
        for measurement in measures:
            assay = measurement.assay
            protocol = assay.protocol
            line = assay.line
            if self.options.line_section:
                line_only = [Line, Study, ]
                other_only = [Assay, Measurement, Protocol, ]
                # add row to line table w/ Study, Line columns only
                if line.id not in tables['line']:
                    row = self._output_row_with_measure(measurement, models=line_only)
                    tables['line'][line.id] = row
                # create row for protocol/all table w/ Protocol, Assay, Measurement columns only
                row = self._output_row_with_measure(measurement, models=other_only)
            else:
                # create row for protocol/all table
                row = self._output_row_with_measure(measurement)
            table, table_key = self._init_tables_for_protocol(tables, protocol)
            values = measurement.measurementvalue_set.all()  # prefetched above
            if self.options.layout == ExportOption.DATA_COLUMN_BY_POINT:
                for value in values:
                    arow = row[:]
                    arow.append(value_str(value.x))
                    arow.append(value_str(value.y))
                    table[value.id] = arow
            else:
                # keep track of all x values encountered in the table
                xx = self._x_values[table_key] = self._x_values.get(table_key, {})
                # do value_str to the float-casted version of x to eliminate 0-padding
                xx.update({value_str(v.x): v.x for v in values})
                squashed = {value_str(v.x): value_str(v.y) for v in values}
                row.append(squashed)
                table[measurement.id] = row

    def _init_tables_for_protocol(self, tables, protocol):
        if self.options.protocol_section:
            if protocol.id not in tables:
                tables[protocol.id] = OrderedDict()
                header = []
                if self.options.line_section:
                    header += self._output_measure_header()
                else:
                    header += self._output_header()
                tables[protocol.id]['header'] = header
            table_key = protocol.id
        else:
            table_key = 'all'
        table = tables[table_key]
        return (table, table_key)

    def _output_header(self, models=None):
        row = []
        for column in self.options.columns:
            if models is None or column._model in models:
                row.append(column.get_heading())
        if self.options.layout == ExportOption.DATA_COLUMN_BY_POINT:
            row.append('X')
            row.append('Y')
        return row

    def _output_line_header(self):
        from main.models import Line, Study
        return self._output_header([Line, Study, ])

    def _output_row_with_line(self, line, protocol, models=None, columns=None, **kwargs):
        row = []
        if columns is None:
            columns = self.options.columns
        for i, column in enumerate(columns):
            if models is None or column._model in models:
                instance = column.convert_instance_from_line(line, protocol)
                row.append(column.get_value(instance, **kwargs))
        return row

    def _output_row_with_measure(self, measure, models=None):
        row = []
        for column in self.options.columns:
            if models is None or column._model in models:
                instance = column.convert_instance_from_measure(measure)
                row.append(column.get_value(instance))
        return row

    def _output_measure_header(self):
        from main.models import Assay, Measurement, Protocol
        return self._output_header([Assay, Measurement, Protocol, ])

    def _output_unsquash(self, all_x, squashed):
        # all_x is list of 2-tuple from dict.items()
        if isinstance(squashed, dict):
            return map(lambda x: squashed.get(x[0], ''), all_x)
        # expecting a list to be returned
        return [squashed]


class WorklistExport(TableExport):
    """ Outputs tables for line worklists. """
    def __init__(self, selection, options, worklist=None):
        super(WorklistExport, self).__init__(selection, options)
        self.worklist = worklist

    def output(self):
        # store tables
        tables = OrderedDict()
        tables['all'] = OrderedDict()
        tables['all']['header'] = self._output_header()
        if self.worklist and self.worklist.protocol:
            self._do_worklist(tables)
        return self._build_output(tables)

    def _do_worklist(self, tables):
        # if export is a worklist, go off of lines instead of measurements
        lines = self.selection.lines
        protocol = self.worklist.protocol
        table = tables['all']
        # lines is a QuerySet of the lines to use in worklist creation
        for i, line in enumerate(lines):
            # build row with study/line info
            row = self._output_row_with_line(line, protocol)
            table[str(line.pk)] = row
            # when modulus set, insert 'blank' row every modulus rows
            if self.options.blank_mod and not (i + 1) % self.options.blank_mod:
                blank = self._output_row_with_line(
                    None, protocol, columns=self.options.blank_columns
                )
                table['blank%s' % i] = blank
