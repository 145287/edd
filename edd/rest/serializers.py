"""
Defines serializers for EDD's nascent REST API, as supported by the django rest framework
(http://www.django-rest-framework.org/)
"""

from main.models import (EDDObject, Line, MetadataType, MetadataGroup, Strain, Study, Update,
                         User, Protocol, MeasurementUnit)
from rest_framework import serializers


###################################################################################################
# unused
###################################################################################################
class UpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Update
        fields = ('mod_time', 'mod_by', 'path', 'origin')
        depth = 0
###################################################################################################


class EDDObjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = EDDObject
        fields = ('pk', 'name', 'description', 'uuid', 'created', 'updated', 'meta_store',
                  'active')


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


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        depth = 0


class MetadataTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = MetadataType
        depth = 0
        fields = ('pk', 'uuid', 'type_name', 'type_i18n', 'input_size', 'input_type',
                  'default_value', 'prefix', 'postfix', 'for_context', 'type_class', 'group')


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
