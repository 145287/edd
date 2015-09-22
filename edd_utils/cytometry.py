
import json
import logging
import re

from collections import defaultdict

from main.models import (
    Assay, Line, Measurement, MeasurementCompartment, MeasurementFormat, MeasurementUnit,
    MeasurementValue, Protocol,
    )


logger = logging.getLogger(__name__)


class CytometerImport(object):
    """ Object to handle processing of data POSTed to /utilities/cytometry/import view and add
        measurements to the database. """

    def __init__(self, request):
        self._request = request
        self._qd = request.POST
        self._rows = {}
        # this should be unique
        self._protocol = Protocol.objects.filter(
            name='Flow Cytometry Characterization',
            owned_by__is_superuser=True,
            )[0]

    def load_assay_for(self, i, study):
        qd = self._qd
        assay_id = qd.get('assay%s' % i, None)
        assay = None
        if assay_id == 'new':
            line_id = qd.get('line%s' % i, None)
            sample_name = qd.get('sample%s' % i, None)
            if line_id == 'new' and study:
                line = study.line_set.create(
                    name='Imported %s' % (study.line_set.count() + 1),
                    contact=self._request.user,
                    experimenter=self._request.user,
                    )
            elif line_id:
                line = Line.objects.get(pk=line_id)
            if line:
                assay = line.assay_set.create(
                    name='%s-%s' % (line.name, sample_name),
                    protocol=self._protocol,
                    experimenter=self._request.user,
                    )
            else:
                assay = None
        elif assay_id == 'ignore':
            assay = None
        elif assay_id:
            assay = Assay.objects.get(pk=assay_id)
        return assay

    def process(self, study):
        data = json.loads(self._qd.get('data', '[]'))
        time = self._qd.get('time', 0)
        # first pass through import data
        for (i, row) in enumerate(data):
            assay = self.load_assay_for(i, study)
            self.process_row(i, row, assay)
        # check for any standards rows 
        # TODO modify measurements based on selected standard rows
        # compose rows of data into Measurements to add to assay
        for row in self._rows.values():
            row.compose(time)

    def process_cell(self, j, cell, obj):
        col = self._qd.get('column%s' % j, None)
        if col == 'avg':
            obj.define_measurement(j, self._qd.get('type%s' % j, None), cell)
        elif col == 'std':
            obj.define_deviation(self._qd.get('std%s' % j, None), cell)
        elif col == 'cv':
            obj.define_variance(self._qd.get('cv%s' % j, None), cell)
        elif col == 'count':
            obj.define_count(cell)
        elif col == 'meta':
            obj.define_metadata(self._qd.get('meta%s' % j, None), cell)
        elif col == 'viab':
            obj.define_viable(cell)

    def process_row(self, i, row, assay):
        obj = CytometerRow(assay)
        for (j, cell) in enumerate(row):
            # look up how to handle column j, add to obj
            self.process_cell(j, cell, obj)
        if assay:
            self._rows[i] = obj


class CytometerRow(object):
    hours = MeasurementUnit.objects.get(unit_name='hours')
    na = MeasurementUnit.objects.get(unit_name='n/a') # FIXME probably don't want to use n/a

    def __init__(self, assay):
        self._assay = assay
        self._measure_data = defaultdict(dict)
        self._count = None
        self._viable = None

    def compose(self, time):
        if self._viable and self._count:
            self._count = self._count * self._viable
        for seq, measure in self._measure_data.items():
            ptype = measure.get('ptype', None)
            value = measure.get('value', None)
            variance = measure.get('variance', None)
            if variance is None:
                dev = measure.get('deviation', None)
                if dev and value:
                    variance = dev / value
            try:
                obj = self._assay.measurement_set.get(measurement_type_id=ptype)
            except Measurement.DoesNotExist:
                obj = self._assay.measurement_set.create(
                    measurement_type_id=ptype,
                    measurement_format=MeasurementFormat.SIGMA,
                    compartment=MeasurementCompartment.UNKNOWN,
                    x_units=self.hours,
                    y_units=self.na,
                    )
            x = map(float, [ time, ])
            y = map(float, [ value, variance, self._count, ])
            try:
                point = obj.measurementvalue_set.get(x=x)
            except MeasurementValue.DoesNotExist:
                point = obj.measurementvalue_set.create(x=x, y=y)
            else:
                point.y = y
                point.save()
        # make sure metadata set gets saved
        self._assay.save()

    def define_count(self, value):
        try:
            self._count = int(value)
        except ValueError:
            print("Invalid count value")

    def define_deviation(self, seq, value):
        seq = unicode(seq)  # ensure sequence is a string
        try:
            dev = float(value)
        except ValueError:
            print("Invalid deviation value")
        else:
            self._measure_data[seq]['deviation'] = dev

    def define_measurement(self, seq, ptype, value):
        seq = unicode(seq)  # ensure sequence is a string
        try:
            avg = float(value)
        except ValueError:
            print("Invalid average value")
        else:
            self._measure_data[seq].update({
                'ptype': ptype,
                'value': avg,
                })

    def define_metadata(self, meta_type, value):
        if self._assay: # could be an ignored row without an assay
            self._assay.meta_store[meta_type] = value

    def define_variance(self, seq, value):
        seq = unicode(seq)  # ensure sequence is a string
        try:
            if unicode(value)[-1] == u'%':
                cv = float(unicode(value)[:-1]) / 100
            else:
                cv = float(value)
        except ValueError:
            print("Invalid cv value '%s'" % value)
        else:
            self._measure_data[seq]['variance'] = cv

    def define_viable(self, value):
        try:
            if unicode(value)[-1] == u'%':
                viable = float(unicode(value)[:-1]) / 100
            else:
                viable = float(value)
        except ValueError:
            print("Invalid viable value '%s'" % value)
        else:
            self._viable = viable
