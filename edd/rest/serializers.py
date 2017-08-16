"""
Defines serializers for EDD's nascent REST API, as supported by the Django Rest Framework
(http://www.django-rest-framework.org/)
"""

from rest_framework import serializers

from main.models import (Assay, GeneIdentifier, Line, Measurement, MeasurementType,
                         MeasurementUnit, MeasurementValue, Metabolite, MetadataGroup,
                         MetadataType, Phosphor,
                         ProteinIdentifier, Protocol, Strain, Study, Update, User)


###################################################################################################
# unused
###################################################################################################
class UpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Update
        fields = ('mod_time', 'mod_by', 'path', 'origin')
        depth = 0
###################################################################################################


_MEASUREMENT_TYPE_FIELDS = ('pk', 'uuid', 'type_name', 'type_group', 'type_source', 'alt_names')


class AssaySerializer(serializers.ModelSerializer):
    class Meta:
        model = Assay
        fields = ('pk', 'line', 'name', 'protocol', 'experimenter', 'description', 'uuid',
                  'created', 'updated', 'meta_store', 'active')


class MeasurementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Measurement
        fields = ('pk', 'assay', 'experimenter', 'measurement_type', 'x_units',
                  'y_units', 'compartment', 'active', 'update_ref', 'measurement_format')


class MeasurementValueSerializer(serializers.ModelSerializer):
    class Meta:
        model = MeasurementValue
        fields = ('pk', 'measurement', 'x', 'y', 'updated')


class StudySerializer(serializers.ModelSerializer):
    class Meta:
        model = Study
        fields = ('pk', 'name', 'description', 'uuid', 'slug',  'created', 'updated', 'contact',
                  'contact_extra', 'metabolic_map', 'meta_store', 'active')

        # disable editable DB fields where write access shoulde be hidden for unprivileged users
        read_only_fields = ('slug', 'meta_store')
        depth = 0
        lookup_field = 'study'


class LineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Line
        fields = ('pk', 'uuid', 'study', 'name', 'description', 'control', 'replicate', 'contact',
                  'experimenter', 'protocols', 'strains', 'meta_store', 'active')
        carbon_source = serializers.StringRelatedField(many=False)
        depth = 0

        def create(self, validated_data):
            """
            Create and return a new Line instance, given the validated data
            """
            return Line.objects.create(**validated_data)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        depth = 0
        fields = ('pk', 'username', 'first_name', 'last_name', 'email', 'is_active')


class MetadataTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = MetadataType
        depth = 0
        fields = ('pk', 'uuid', 'type_name', 'type_i18n', 'input_size', 'input_type',
                  'default_value', 'prefix', 'postfix', 'for_context', 'type_class', 'group')


class MeasurementTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = MeasurementType
        depth = 0
        fields = _MEASUREMENT_TYPE_FIELDS


class MetaboliteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Metabolite
        depth = 0
        fields = _MEASUREMENT_TYPE_FIELDS + ('charge', 'carbon_count', 'molar_mass',
                                             'molecular_formula', 'smiles', 'id_map', 'tags')


class ProteinIdSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProteinIdentifier
        depth = 0
        fields = _MEASUREMENT_TYPE_FIELDS + ('accession_id', 'length', 'mass')


class GeneIdSerializer(serializers.ModelSerializer):
    class Meta:
        model = GeneIdentifier
        depth = 0
        fields = _MEASUREMENT_TYPE_FIELDS + ('location_in_genome', 'positive_strand',
                                             'location_start', 'location_end', 'gene_length')


class PhosphorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Phosphor
        depth = 0
        fields = _MEASUREMENT_TYPE_FIELDS + ('excitation_wavelength', 'emission_wavelength',
                                             'reference_type')


class MeasurementUnitSerializer(serializers.ModelSerializer):
    class Meta:
        model = MeasurementUnit
        depth = 0
        fields = ('pk', 'unit_name', 'display', 'alternate_names', 'type_group')


class ProtocolSerializer(serializers.ModelSerializer):
    class Meta:
        model = Protocol
        depth = 0
        fields = ('pk', 'uuid', 'name', 'description', 'owned_by', 'variant_of', 'default_units',
                  'categorization')


class MetadataGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = MetadataGroup
        depth = 0


class StrainSerializer(serializers.ModelSerializer):

    class Meta:
        model = Strain

        fields = ('name', 'description', 'registry_url', 'registry_id', 'pk')
        depth = 0

    # def __init__(self, instance=None, data=empty, **kwargs):
    #      super(StrainSerializer, self).__init__(instance, data, **kwargs)

    # work around an apparent oversite in ModelSerializer's __new__ implementation that prevents us
    # from using it to construct new objects from a class instance with kw arguments similar to its
    # __init__() method
    # @staticmethod
    # def __new__(cls, *args, **kwargs):
    #     kwargs.pop('data', empty)
    #     kwargs.pop('instance', None)
    #     return serializers.ModelSerializer.__new__(cls, *args, **kwargs)
