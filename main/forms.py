# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import logging

from builtins import str
from collections import OrderedDict
from copy import deepcopy
from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.postgres.forms import HStoreField
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Prefetch, Q
from django.db.models.base import Model
from django.db.models.manager import BaseManager
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
from form_utils.forms import BetterModelForm
from functools import partial

from jbei.rest.auth import HmacAuth
from jbei.ice.rest.ice import IceApi
from .export import table
from .models import (
    Assay, Attachment, CarbonSource, Comment, Line, Measurement, MeasurementType,
    MeasurementValue, MetaboliteExchange, MetaboliteSpecies, MetadataType, Protocol, Strain,
    Study, StudyPermission, Update,
)

User = get_user_model()
logger = logging.getLogger(__name__)


class AutocompleteWidget(forms.widgets.MultiWidget):
    """ Custom widget for a paired autocomplete and hidden ID field. """
    class Media:
        js = (
            'main/js/lib/jquery/jquery.js',
            'main/js/lib/jquery-ui/jquery-ui.min.js',
            'main/js/autocomplete2.js',
            )
        css = {
            'all': (
                'main/js/lib/jquery-ui/jquery-ui.min.css',
                'main/widgets.css',
            ),
        }

    def __init__(self, attrs=None, model=User, opt={}):
        _widgets = (
            forms.widgets.TextInput(attrs=opt.get('text_attr', {})),
            forms.HiddenInput()
            )
        self.model = model
        super(AutocompleteWidget, self).__init__(_widgets, attrs)

    def decompress(self, value):
        # if the value is the actual model instance, don't try to look up model
        if isinstance(value, Model):
            return [self.display_value(value), value.pk]
        elif value:
            o = self.model.objects.get(pk=value)
            return [self.display_value(o), value]
        return ['', None]

    def display_value(self, value):
        return str(value)

    def value_from_datadict(self, data, files, name):
        widgets = enumerate(self.widgets)
        v = [w.value_from_datadict(data, files, name + '_%s' % i) for i, w in widgets]
        # v[0] is text of field, v[1] is hidden ID
        return v[1]


class MultiAutocompleteWidget(AutocompleteWidget):
    """ Extension to Autocomplete widget that handles multiple autocompleted values.
        All values must be lists; either a list of results from decompress, or a list of values
        to be passed to decompress """
    def __init__(self, **kwargs):
        self._separator = kwargs.pop('separator', ',')
        super(MultiAutocompleteWidget, self).__init__(**kwargs)

    def decompress(self, value):
        if isinstance(value, BaseManager):
            # delegate decompress for individual items
            values = map(super(MultiAutocompleteWidget, self).decompress, value.all())
            # zip together into array of two value-arrays
            values = zip(*values)
            if len(values):
                # join by the separator string
                return [
                    self._separator.join(map(str, values[0])),
                    self._separator.join(map(str, values[1])),
                ]
            else:
                # there are no values, return "empty" structure
                return ['', None]
        return super(MultiAutocompleteWidget, self).decompress(value)

    def render(self, name, value, attrs=None):
        joined = []
        _range = range(len(self.widgets))
        for index in _range:
            joined.append([])
        if value is None:
            value = []
        for item in value:
            if not isinstance(item, list):
                item = self.decompress(item)
            for index in _range:
                joined[index].append(item[index] if len(item) > index else '')
        for index in _range:
            joined[index] = self._separator.join(map(str, joined[index]))
        return super(MultiAutocompleteWidget, self).render(name, joined, attrs)

    def value_from_datadict(self, data, files, name):
        # value from super will be joined by self._separator, so split it to get the true value
        joined = super(MultiAutocompleteWidget, self).value_from_datadict(data, files, name)
        if joined:
            return joined.split(self._separator)
        return []


class UserAutocompleteWidget(AutocompleteWidget):
    """ Autocomplete widget for Users """
    def __init__(self, attrs=None, opt={}):
        opt.update({'text_attr': {'class': 'autocomp autocomp_user', }, })
        super(UserAutocompleteWidget, self).__init__(attrs=attrs, model=User, opt=opt)


class GroupAutocompleteWidget(AutocompleteWidget):
    """ Autocomplete widget for Groups """
    def __init__(self, attrs=None, opt={}):
        opt.update({'text_attr': {'class': 'autocomp autocomp_group', }, })
        super(GroupAutocompleteWidget, self).__init__(attrs=attrs, model=Group, opt=opt)


class RegistryValidator(object):
    def __init__(self, existing_strain=None):
        self.existing_strain = existing_strain
        self.count = None
        self.entry = None

    def load_part_from_ice(self, registry_id):
        update = Update.load_update()
        user_email = update.mod_by.email
        try:
            ice = IceApi(auth=HmacAuth(key_id=settings.ICE_KEY_ID, username=user_email))
            self.entry = ice.get_entry(registry_id)
            self.entry.url = ''.join((ice.base_url, '/entry/', str(self.entry.id),))
        except Exception:
            logger.exception('Exception loading part %(part_id)s from ICE for user '
                             '%(user_email)s' % {
                                'part_id': registry_id,
                                'user_email': user_email, })
            raise ValidationError(
                _('Failed to load strain %(uuid)s from ICE'),
                code='ice failure',
                params={"uuid": registry_id},
            )

    def save_strain(self):
        if self.entry and self.existing_strain:
            self.existing_strain.registry_id = self.entry.uuid
            self.existing_strain.registry_url = self.entry.url
            self.existing_strain.save()
        elif self.entry:
            Strain.objects.create(
                name=self.entry.name,
                description=self.entry.short_description,
                registry_id=self.entry.uuid,
                registry_url=self.entry.url,
            )

    def validate(self, value):
        try:
            if isinstance(value, (list, tuple)):
                for v in value:
                    self.validate(v)
                return
            qs = Strain.objects.filter(registry_id=value)
            if self.existing_strain:
                qs = qs.exclude(pk__in=[self.existing_strain])
            self.count = qs.count()
            if self.count == 0:
                logger.info('No EDD Strain found with registry_id %s. Searching ICE...', value)
                self.load_part_from_ice(value)
                self.save_strain()
            elif self.count > 1:
                raise ValidationError(
                    _('Selected ICE record is already linked to EDD strains: %(strains)s'),
                    code='existing records',
                    params={"strains": list(qs), },
                )
        except ValueError:
            raise ValidationError(
                _('Error querying for an EDD strain with registry_id %(uuid)s'),
                code='query failure',
                params={"uuid": value, },
            )


class RegistryAutocompleteWidget(AutocompleteWidget):
    """ Autocomplete widget for Registry strains """
    def __init__(self, attrs=None, opt={}):
        opt.update({'text_attr': {'class': 'autocomp autocomp_reg', }, })
        super(RegistryAutocompleteWidget, self).__init__(attrs=attrs, model=Strain, opt=opt)

    def decompress(self, value):
        """ Overriding since Strain uses registry_id for lookups. """
        if isinstance(value, Strain):
            return [self.display_value(value), value.registry_id, ]
        elif value:
            try:
                o = Strain.objects.get(registry_id=value)
                return [self.display_value(o), value, ]
            except Strain.DoesNotExist:
                pass
        return ['', None, ]


class MultiRegistryAutocompleteWidget(MultiAutocompleteWidget, RegistryAutocompleteWidget):
    pass


class CarbonSourceAutocompleteWidget(AutocompleteWidget):
    """ Autocomplete widget for carbon sources """
    def __init__(self, attrs=None, opt={}):
        opt.update({'text_attr': {'class': 'autocomp autocomp_carbon', }, })
        super(CarbonSourceAutocompleteWidget, self).__init__(
            attrs=attrs, model=CarbonSource, opt=opt)

    def display_value(self, value):
        return value.name


class MultiCarbonSourceAutocompleteWidget(MultiAutocompleteWidget, CarbonSourceAutocompleteWidget):
    pass


class MetadataTypeAutocompleteWidget(AutocompleteWidget):
    """ Autocomplete widget for types of metadata """
    def __init__(self, attrs=None, opt={}):
        opt.update({'text_attr': {'class': 'autocomp autocomp_type', }, })
        super(MetadataTypeAutocompleteWidget, self).__init__(
            attrs=attrs, model=MetadataType, opt=opt)


class MeasurementTypeAutocompleteWidget(AutocompleteWidget):
    """ Autocomplete widget for types of metadata """
    def __init__(self, attrs=None, opt={}):
        """ Set opt with {'text_attr': {'class': 'autocomp autocomp_XXX'}} to override. """
        my_opt = {'text_attr': {'class': 'autocomp autocomp_measure', }, }
        my_opt.update(**opt)
        super(MeasurementTypeAutocompleteWidget, self).__init__(
            attrs=attrs, model=MeasurementType, opt=my_opt,
        )


class SbmlInfoAutocompleteWidget(AutocompleteWidget):
    """ Autocomplete widget for parts contained within SBMLTemplate """
    def __init__(self, template, model, attrs=None, opt={}):
        self._template = template
        opt.get('text_attr', {}).update({'data-template': template.pk})
        super(SbmlInfoAutocompleteWidget, self).__init__(attrs=attrs, model=model, opt=opt)

    def decompress(self, value):
        # if the value is the actual model instance, don't try to look up model
        if isinstance(value, self.model):
            return [self.display_value(value), value.pk]
        elif value:
            o = self.lookup(value)
            return [self.display_value(o), o.pk]
        return ['', None]

    def decompress_q(self, value):
        return Q(pk=self._int(value))

    def lookup(self, value):
        try:
            return self.model.objects.get(self.decompress_q(value), sbml_template=self._template)
        except self.model.DoesNotExist:
            pass
        return None

    def value_from_datadict(self, data, files, name):
        widgets = enumerate(self.widgets)
        v = [w.value_from_datadict(data, files, name + '_%s' % i) for i, w in widgets]
        # v[0] is text of field, v[1] is hidden ID
        return self.lookup(v[1])

    def _int(self, value):
        'Try casting a value to int, return None if fails'
        try:
            return int(value)
        except:
            pass
        return None


class SbmlExchangeAutocompleteWidget(SbmlInfoAutocompleteWidget):
    """ Autocomplete widget for Exchanges in an SBMLTemplate """
    def __init__(self, template, attrs=None, opt={}):
        opt.update(text_attr={'class': 'autocomp autocomp_sbml_r'})
        super(SbmlExchangeAutocompleteWidget, self).__init__(
            template=template, attrs=attrs, model=MetaboliteExchange, opt=opt
        )

    def decompress_q(self, value):
        parent = super(SbmlExchangeAutocompleteWidget, self).decompress_q(value)
        return parent | Q(exchange_name=value)


class SbmlSpeciesAutocompleteWidget(SbmlInfoAutocompleteWidget):
    """ Autocomplete widget for Species in an SBMLTemplate """
    def __init__(self, template, attrs=None, opt={}):
        opt.update(text_attr={'class': 'autocomp autocomp_sbml_s'})
        super(SbmlSpeciesAutocompleteWidget, self).__init__(
            template=template, attrs=attrs, model=MetaboliteSpecies, opt=opt
        )

    def decompress_q(self, value):
        parent = super(SbmlSpeciesAutocompleteWidget, self).decompress_q(value)
        return parent | Q(species=value)


class CreateStudyForm(forms.ModelForm):
    """ Form to create a new study. """
    class Meta:
        model = Study
        fields = ['name', 'description', 'contact', ]
        labels = {
            'name': _('Study Name'),
            'description': _('Description'),
            'contact': _('Contact'),
        }
        widgets = {
            'name': forms.widgets.TextInput(attrs={'size': 50}),
            'description': forms.widgets.Textarea(attrs={'cols': 100}),
            'contact': UserAutocompleteWidget(),
        }

    def __init__(self, *args, **kwargs):
        # removes default hard-coded suffix of colon character on all labels
        kwargs.setdefault('label_suffix', '')
        super(CreateStudyForm, self).__init__(*args, **kwargs)

    def save(self, commit=True, force_insert=False, force_update=False, *args, **kwargs):

        # perform updates atomically to the study and related user permissions
        with transaction.atomic():
            # save the study
            s = super(CreateStudyForm, self).save(commit=commit, *args, **kwargs)
            # make sure the creator has write permission, and ESE has read
            s.userpermission_set.update_or_create(
                user=s.created.mod_by,
                permission_type=StudyPermission.WRITE,
            )

            # get the ID of the group that should have study read permissions by default.
            # TODO: this should be configurable in a later version, but for now we'll hard/code
            # in a way that tolerates non-existence / removal of the default group used at JBEI
            default_group_name = 'ESE'
            try:
                default_group= Group.objects.get(name=default_group_name)
                s.grouppermission_set.update_or_create(
                        group_id=default_group.pk,
                        permission_type=StudyPermission.READ, )
            except Group.DoesNotExist as dne:
                logger.exception('Error retrieving information for the hard-coded default-read '
                                 'group for studies, "%s". Studies will not default to visible '
                                 'for any particular group.' %
                                 default_group_name)

        return s


class CreateAttachmentForm(forms.ModelForm):
    """ Form to create a new attachment. """
    class Meta:
        model = Attachment
        fields = ('file', 'description', )
        labels = {
            'file': _('Attachment'),
            'description': _('Description'),
        }
        widgets = {
            'description': forms.widgets.TextInput(),
        }

    def __init__(self, *args, **kwargs):
        # removes default hard-coded suffix of colon character on all labels
        kwargs.setdefault('label_suffix', '')
        # store the parent EDDObject
        self._parent = kwargs.pop('edd_object', None)
        super(CreateAttachmentForm, self).__init__(*args, **kwargs)

    def save(self, commit=True, force_insert=False, force_update=False, *args, **kwargs):
        a = super(CreateAttachmentForm, self).save(commit=False, *args, **kwargs)
        a.object_ref = self._parent
        if commit:
            a.save()
        return a


class CreateCommentForm(forms.ModelForm):
    """ Form to create a new comment. """
    class Meta:
        model = Comment
        fields = ('body', )
        labels = {
            'body': _('')
        }

    def __init__(self, *args, **kwargs):
        # removes default hard-coded suffix of colon character on all labels
        kwargs.setdefault('label_suffix', '')
        # store the parent EDDObject
        self._parent = kwargs.pop('edd_object', None)
        super(CreateCommentForm, self).__init__(*args, **kwargs)

    def save(self, commit=True, force_insert=False, force_update=False, *args, **kwargs):
        c = super(CreateCommentForm, self).save(commit=False, *args, **kwargs)
        c.object_ref = self._parent
        if commit:
            c.save()
        return c


class EDDHStoreField(HStoreField):
    def to_python(self, value):
        if not value:
            return {}
        try:
            value = json.loads(value)
        except ValueError:
            raise ValidationError(
                self.error_messages['invalid_json'],
                code='invalid_json',
            )
        return value


class LineForm(forms.ModelForm):
    """ Form to create/edit a line. """
    # include hidden field for applying form changes to multiple Line instances by ID
    ids = forms.CharField(required=False, widget=forms.HiddenInput())

    class Meta:
        model = Line
        fields = (
            'name', 'description', 'control', 'contact', 'experimenter', 'carbon_source',
            'strains', 'meta_store',
        )
        labels = {
            'name': _('Line'),
            'description': _('Description'),
            'control': _('Is Control?'),
            'contact': _('Contact'),
            'experimenter': _('Experimenter'),
            'carbon_source': _('Carbon Source'),
            'strains': _('Strains'),
        }
        widgets = {
            'description': forms.Textarea(attrs={'rows': 2}),
            'contact': UserAutocompleteWidget(),
            'experimenter': UserAutocompleteWidget(),
            'carbon_source': MultiCarbonSourceAutocompleteWidget(),
            'strains': MultiRegistryAutocompleteWidget(),
            'meta_store': forms.HiddenInput(),
        }

    def __init__(self, *args, **kwargs):
        # removes default hard-coded suffix of colon character on all labels
        kwargs.setdefault('label_suffix', '')
        # store the parent Study
        self._study = kwargs.pop('study', None)
        super(LineForm, self).__init__(*args, **kwargs)
        self.fields['name'].error_messages =  {'required': 'Line name is required'}
        self.fields['name'].help_text = 'This field is required.'
        # alter all fields to include a "bulk-edit" checkbox in label
        # initially hidden via "off" class
        for fieldname, field in self.fields.items():
            field.label = mark_safe(
                '<input type="checkbox" class="off bulk" name="%s" checked="checked" '
                'value/>%s' % (self.add_prefix('_bulk_%s' % fieldname), field.label)
                )
        # make sure strain is keyed by registry_id instead of pk, and validates uuid
        strains_field = self.fields['strains']

        def __clean(self, value):
            # validator creates Strain record if missing, now can check value
            for v in value:
                self.run_validators(v)
            return self.__clean(value)
        strains_field.__clean = strains_field.clean
        strains_field.clean = partial(__clean, strains_field)
        strains_field.to_field_name = 'registry_id'
        strains_field.validators = [RegistryValidator().validate, ]
        # keep a flag for bulk edit, treats meta_store slightly differently
        self._bulk = False
        # override form field handling of HStore
        meta = self.fields['meta_store']
        meta.to_python = EDDHStoreField.to_python.__get__(meta, EDDHStoreField)

    @classmethod
    def initial_from_model(cls, line, prefix=None):
        """ Builds a dict of initial form values from a Line model """
        initial = {}
        for fieldname in cls._meta.fields:
            widget = cls._meta.widgets.get(fieldname, None)
            value = getattr(line, fieldname)
            fieldkey = '%s-%s' % (prefix, fieldname) if prefix else fieldname
            # need to split MultiWidget values into each widget value
            if isinstance(widget, forms.widgets.MultiWidget):
                for i, part in enumerate(widget.decompress(value)):
                    initial['%s_%s' % (fieldkey, i)] = part
            # HStoreField gives back a dict; must serialize to json
            elif isinstance(value, dict):
                initial[fieldkey] = json.dumps(value)
            # everything else shove value into fieldname
            else:
                initial[fieldkey] = str(value)
        return initial

    def check_bulk_edit(self):
        self._bulk = True
        exclude = []
        # Look for "bulk-edit" checkboxes for each field
        for field in self.visible_fields():
            check = self.add_prefix('_bulk_%s' % field.name)
            if check not in self.data:
                exclude.append(field.name)
        # remove fields without a check from self, preventing processing
        for fieldname in exclude:
            # Removing excluded key from fields
            del self.fields[fieldname]

    def clean_meta_store(self):
        # go through and delete any keys with None values
        meta = self.cleaned_data['meta_store']
        none_keys = []
        for key, value in meta.items():
            if value is None:
                none_keys.append(key)
        for key in none_keys:
            # Removing None-valued key from meta
            del meta[key]
        if self.is_editing() and self._bulk:
            # Bulk edit updating meta_store
            in_place = {}
            in_place.update(self.instance.meta_store)
            in_place.update(meta)
            meta = in_place
        return meta

    def is_editing(self):
        return self.instance.pk is not None

    def save(self, commit=True, force_insert=False, force_update=False, *args, **kwargs):
        line = super(LineForm, self).save(commit=False, *args, **kwargs)
        line.study = self._study
        if commit:
            line.save()
            # since we forced commit=False in the first save, need to explicitly call save_m2m
            self.save_m2m()
        return line


class AssayForm(forms.ModelForm):
    """ Form to create/edit an assay. """
    # include hidden field for applying form changes to an Assay instance by ID
    assay_id = forms.CharField(required=False, widget=forms.HiddenInput())

    class Meta:
        model = Assay
        fields = (
            'name', 'description', 'protocol', 'experimenter',
        )
        help_texts = {
            'name': _('If left blank, a name in form [Line]-[Protocol]-[#] will be generated. '),
        }
        labels = {
            'name': _('Name'),
            'description': _('Description'),
            'protocol': _('Protocol'),
            'experimenter': _('Experimenter'),
        }
        widgets = {
            'description': forms.Textarea(attrs={'rows': 2}),
            'experimenter': UserAutocompleteWidget(),
        }

    def __init__(self, *args, **kwargs):
        # removes default hard-coded suffix of colon character on all labels
        kwargs.setdefault('label_suffix', '')
        # store the parent Line
        self._lines = kwargs.pop('lines', [])
        super(AssayForm, self).__init__(*args, **kwargs)
        self.fields['protocol'].queryset = Protocol.objects.order_by('name')

    def is_editing(self):
        return self.instance.pk is not None

    def save(self, commit=True, force_insert=False, force_update=False, *args, **kwargs):
        assay = super(AssayForm, self).save(commit=False, *args, **kwargs)

        # quick function to copy assay instance from form, and set to correct line
        def link_assay(line_id):
            clone = deepcopy(assay)
            clone.line_id = line_id
            return clone
        all_assays = map(link_assay, self._lines)
        if commit:
            [a.save() for a in all_assays]
        return all_assays


class MeasurementForm(forms.ModelForm):
    """ Form to create/edit a measurement. """
    class Meta:
        model = Measurement
        fields = ('measurement_type', 'y_units', 'compartment', )
        help_texts = {
            'measurement_type': _(''),
            'y_units': _('Select the units used for these measurements'),
            'compartment': _('(optional) Select if the measurement is inside or outside'
                             ' the organism')
        }
        labels = {
            'measurement_type': _('Type'),
            'y_units': _('Units'),
            'compartment': _('Compartment'),
        }
        widgets = {
            'measurement_type': MeasurementTypeAutocompleteWidget(),
        }

    def __init__(self, *args, **kwargs):
        # removes default hard-coded suffix of colon character on all labels
        kwargs.setdefault('label_suffix', '')
        # store the parent Assays
        self._assays = kwargs.pop('assays', [])
        super(MeasurementForm, self).__init__(*args, **kwargs)

    def save(self, commit=True, force_insert=False, force_update=False, *args, **kwargs):
        measure = super(MeasurementForm, self).save(commit=False, *args, **kwargs)

        # quick function to copy measurement instance from form, and set to correct assay
        def link_measure(assay_id):
            clone = deepcopy(measure)
            clone.assay_id = assay_id
            return clone
        all_measures = map(link_measure, self._assays)
        if commit:
            [m.save() for m in all_measures]
        return all_measures


class MeasurementValueForm(BetterModelForm):
    """ Form for an individual measurement value. """
    class Meta:
        fields = ('x', 'y', )
        fieldsets = [('', {'fields': ['x', 'y', ], }), ]
        model = MeasurementValue
        widgets = {
            'x': forms.widgets.NumberInput(),
            'y': forms.widgets.NumberInput(),
        }


MeasurementValueFormSet = forms.models.inlineformset_factory(
    Measurement, MeasurementValue, can_delete=False, extra=0, form=MeasurementValueForm,
)
