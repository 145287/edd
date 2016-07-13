/// <reference path="../typings/underscore/underscore.d.ts"/>;

var GraphHelperMethods;
GraphHelperMethods = {
    /**
     *  This function takes in data and transforms it into the following
     *  {x, y, i}, {x, y, i}, {x, y, i} ....
    **/
    sortBarData: function (assays) {
        return [].concat.apply([], assays);
    },
    /**
     *  This function takes a unit id and unit type json and returns the unit name
    **/
    unitName: function (unitId, unitTypes) {
        return unitTypes[unitId].name;
    },
    /**
     *  This function takes a unit id and unit type json and returns the unit name
    **/
    createSvg: function (selector) {
        var svg = d3.select(selector).append("svg")
            .attr("preserveAspectRatio", "xMinYMin meet")
            .attr("viewBox", "-45 -30 1100 280")
            .classed("svg-content", true);
        return svg;
    },
    /**
     *  This function takes in EDDdata, a singleAssay line entry, and measurement names and
     *  transforms it into the following schema:
     *    [{label: "dt9304, x: 1, y: 2.5, x_unit: "n/a", y_unit: "cmol",  name: "i'm a protein
     *    name"},
     *    {label: "dt3903, x: 1, y: 23.5, x_unit: "n/a", y_unit: "cmol",  name: "i'm another protein
     *    name"}
     *    ...
     *    ]
    **/
    transformSingleLineItem: function (data, singleData, names) {
        // unit type ids
        var unitTypes = data.UnitTypes;
        // array of x and y values for sortin
        var xAndYValues = [];
        //data for one line entry
        var singleDataValues = singleData.values;
        _.forEach(singleDataValues, function (dataValue) {
            var dataset = {};
            //can also change to omit data point with null which was done before..
            if (dataValue[0].length == 0) {
                dataValue[0] = ["0"];
            }
            else if (dataValue[1].length == 0) {
                dataValue[1] = ["0"];
            }
            dataset['label'] = 'dt' + singleData.assay;
            dataset['x'] = parseFloat(dataValue[0].join());
            dataset['y'] = parseFloat(dataValue[1].join());
            dataset['x_unit'] = GraphHelperMethods.unitName(singleData.x_units, unitTypes);
            dataset['y_unit'] = GraphHelperMethods.unitName(singleData.y_units, unitTypes);
            dataset['name'] = names;
            xAndYValues.push(dataset);
        });
        xAndYValues.sort(function (a, b) {
            return a.x - b.x;
        });
        return xAndYValues;
    },
    /**
     * this function returns an object of y units with counts
    **/
    findY_Units: function (data) {
        var yUnits = {};
        _.each(data, function (lineEntry) {
            var y_unit = lineEntry.y_unit;
            if (yUnits.hasOwnProperty(lineEntry.y_unit)) {
                yUnits[y_unit]++;
            }
            else {
                yUnits[y_unit] = 0;
            }
        });
        return Object.keys(yUnits);
    },
    /**
     * this function returns an object of x_values
    **/
    findX_Units: function (data) {
        var xUnits = {};
        _.each(data, function (lineEntry) {
            var x_unit = lineEntry.x_unit;
            if (xUnits.hasOwnProperty(lineEntry.x_unit)) {
                xUnits[x_unit]++;
            }
            else {
                xUnits[x_unit] = 0;
            }
        });
        return Object.keys(xUnits);
    },
    /**
     *  This function takes in the EDDData.AssayMeasurements object and returns
     *  an array of Assay ids.
    **/
    findAssayIds: function (assayMeasurements) {
        var assayIds = [];
        for (var key in assayMeasurements) {
            assayIds.push(assayMeasurements[key].assay);
        }
        return assayIds;
    },
    /**
     *  This function takes in the EDDData.Assays object and array of Assay ids
     *  and returns an array of LID ids.
    **/
    findLidIds: function (assays, assayIds) {
        var lidIds = [];
        _.forEach(assayIds, function (assayId) {
            lidIds.push(assays[assayId].lid);
        });
        return lidIds;
    },
    /**
     *  This function takes in the EDDData.Lines object and lidIds and returns
     *  an array of measurements names.
    **/
    lineName: function (lines, lidIds) {
        var lineNames = [];
        _.forEach(lidIds, function (lidId) {
            lineNames.push(lines[lidId].name);
        });
        return lineNames;
    },
    /**
     * This function returns object size
    **/
    objectSize: function (object) {
        var size = 0, key;
        for (key in object) {
            if (object.hasOwnProperty(key))
                size++;
        }
        return size;
    },
    /**
     *   This function takes in the EDDData object and returns
     *  an array of measurements names.
    **/
    names: function (EDDData) {
        var assayIds = GraphHelperMethods.findAssayIds(EDDData.AssayMeasurements);
        var lidIds = GraphHelperMethods.findLidIds(EDDData.Assays, assayIds);
        return GraphHelperMethods.lineName(EDDData.Lines, lidIds);
    },
    /**
     *  This function returns the legend svg object.
    **/
    legend: function (data, color, svg, width, names) {
        var legend = svg.selectAll(".legend")
            .data(data)
            .enter().append("g")
            .attr("class", "legend")
            .attr("transform", function (d, i) {
            return "translate(0," + i * 20 + ")";
        });
        legend.append("rect")
            .attr("x", width + 5)
            .attr("width", 18)
            .attr("height", 18)
            .style("fill", function (d) {
            return data.color = color(d.key);
        });
        legend.append("text")
            .attr("x", width + 25)
            .attr("y", 9)
            .attr("dy", ".35em")
            .style("text-anchor", "start")
            .text(function (d) {
            return d.key;
        });
        //hide legend for too many entries.
        if (names.length > 10) {
            d3.selectAll(".legend").style("display", "none");
        }
        return legend;
    },
    /**
     *  This function takes in the unit type for each array and returns the text to display on
     *  the axis
    **/
    displayUnit: function (units) {
        if (units.length == 1) {
            return units[0];
        }
        else {
            return "Mixed measurements";
        }
    },
    /**
     *  This function takes in the unit type for each array and returns the text to display on
     *  the axis
    **/
    createXAxis: function (graphSet, x, svg) {
        var xAxis = d3.svg.axis()
            .scale(x)
            .orient("bottom");
        svg.append("g")
            .attr("class", "x axis")
            .attr("transform", "translate(0," + graphSet.height + ")")
            .call(xAxis)
            .append('text')
            .attr("y", 20)
            .attr("x", graphSet.width)
            .text(graphSet.x_unit);
        // Draw the x Grid lines
        // svg.append("g")
        //     .attr("class", "grid")
        //     .attr("transform", "translate(0," + graphSet.height + ")")
        //     .call(xAxis
        //         .tickSize(-graphSet.height, 0, 0)
        //         .tickFormat(""));
    },
    /**
     *  This function takes in the unit type for each array and returns the text to display on
     *  the axis
    **/
    createYAxis: function (graphSet, y, svg) {
        var yAxis = d3.svg.axis()
            .scale(y)
            .orient("left")
            .tickFormat(d3.format(".2s"));
        // Draw the y Grid lines
        // svg.append("g")
        //     .attr("class", "grid")
        //     .call(yAxis
        //         .tickSize(-graphSet.width, 0, 0)
        //         .tickFormat(""));
        svg.append("g")
            .attr("class", "y axis")
            .call(yAxis)
            .append("text")
            .attr("transform", "rotate(-90)")
            .attr("y", 6)
            .attr("dy", ".71em")
            .style("text-anchor", "end")
            .text(graphSet.y_unit);
    }
};