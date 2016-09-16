/// <reference path="../typings/underscore/underscore.d.ts"/>;
var GraphHelperMethods;
GraphHelperMethods = {
    nextColor: null,
    labels: [],
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
     *  This function takes a measurement id and measurement type json and returns the
     *  measurement name
    **/
    measurementName: function (measurementId, measurementTypes) {
        return measurementTypes[measurementId].name;
    },
    /**
     *  This function takes a selector element and returns an svg element
    **/
    createSvg: function (selector) {
        var svg = d3.select(selector).append("svg")
            .attr("preserveAspectRatio", "xMinYMin meet")
            .attr("viewBox", "-55 -30 960 300")
            .classed("svg-content", true);
        return svg;
    },
    /**
     *  This function takes a selector element and returns an svg element
    **/
    createNoAxisSvg: function (selector) {
        var svg = d3.select(selector).append("svg")
            .attr("preserveAspectRatio", "xMinYMin meet")
            .attr("viewBox", "-5 -30 810 300")
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
    transformSingleLineItem: function (dataObj) {
        // unit types
        var unitTypes = dataObj['data'].UnitTypes;
        // measurement types
        var measurementTypes = dataObj['data'].MeasurementTypes;
        // array of x and y values for sorting
        var xAndYValues = [];
        //data for one line entry
        var singleDataValues = dataObj['measure'].values;
        _.each(singleDataValues, function (dataValue, index) {
            var dataset = {};
            //can also change to omit data point with null which was done before..
            if (dataValue[0].length == 0) {
                dataValue[0] = ["0"];
            }
            else if (dataValue[1].length == 0) {
                dataValue[1] = ["0"];
            }
            dataset['label'] = 'dt' + dataObj['measure'].assay;
            dataset['x'] = parseFloat(dataValue[0].join());
            dataset['y'] = parseFloat(dataValue[1].join());
            dataset['x_unit'] = GraphHelperMethods.unitName(dataObj['measure'].x_units, unitTypes);
            dataset['y_unit'] = GraphHelperMethods.unitName(dataObj['measure'].y_units, unitTypes);
            dataset['name'] = dataObj['name'];
            dataset['color'] = dataObj['color'];
            dataset['nameid'] = dataObj['names'] + index;
            dataset['lineName'] = dataObj['lineName'];
            dataset['measurement'] = GraphHelperMethods.measurementName(dataObj['measure'].type, measurementTypes);
            dataset['fullName'] = dataObj['lineName'] + ' ' + dataset['measurement'];
            xAndYValues.push(dataset);
        });
        xAndYValues.sort(function (a, b) {
            return a.x - b.x;
        });
        return xAndYValues;
    },
    /**
    * this function is the same as above but more simple as it is for the import section.
   **/
    transformNewLineItem: function (data, singleData, color) {
        // array of x and y values for sortin
        var xAndYValues = [];
        //data for one line entry
        var singleDataValues = singleData.data;
        _.forEach(singleDataValues, function (dataValue) {
            var dataset = {};
            //can also change to omit data point with null which was done before..
            if (dataValue[0] == null) {
                dataValue[0] = ["0"];
            }
            else if (dataValue[1] == null) {
                dataValue[1] = ["0"];
            }
            dataset['label'] = 'dt' + singleData.assay;
            dataset['x'] = dataValue[0];
            dataset['y'] = parseFloat(dataValue[1]);
            dataset['name'] = singleData.name;
            dataset['color'] = color;
            xAndYValues.push(dataset);
        });
        xAndYValues.sort(function (a, b) {
            return a.x - b.x;
        });
        return xAndYValues;
    },
    /**
     * this function takes in a single line name and study's lines and returns an object of
     * color values with lid keys
     * loosely based on d3 category20 in following link:
     * http://bl.ocks.org/aaizemberg/78bd3dade9593896a59d
    **/
    renderColor: function (line, lines) {
        var colors = {
            0: '#0E6FA4',
            1: '#51BFD8',
            2: '#DA7138',
            3: '#FCA456',
            4: '#2b7b3d',
            5: '#97d37d',
            6: '#CF5030',
            7: '#FFB6C1',
            8: '#6f2f8c',
            9: '#b97dd3',
            10: '#7e0404',
            11: '#BAA0AE',
            12: '#F279BA',
            13: '#993f6c',
            14: '#919191',
            15: '#BFBFBD',
            16: '#ecda3a',
            17: '#b2b200',
            18: '#00d5f2',
            19: '#b2f2fb',
            20: '#0715CD',
            21: '#e8c2f3'
        };
        //new color object with assay ids and color hex
        var lineColors = {};
        //how many lines
        var lineCount = _.range(Object.keys(lines).length);
        //values of line obj
        var lineValues = _.values(lines);
        //new object with numbers for ids
        var indexLines = {};
        // color obj values
        var colorKeys = _.values(colors);
        //create index obj with numbers for ids and assay ids as values
        for (var i = 0; i < lineCount.length; i++) {
            indexLines[i] = lineValues[i].id;
        }
        //if there are more than 22 lines, create a bigger color obj
        if (lineValues.length > colorKeys.length) {
            var multiplier = Math.ceil(lineValues.length / colorKeys.length) * 22;
            GraphHelperMethods.colorMaker(colors, colorKeys, multiplier);
        }
        //combine assay ids as keys with hex colors as values
        _.each(indexLines, function (value, key) {
            lineColors[indexLines[key]] = colors[key];
        });
        for (var key in lines) {
            lines[key]['color'] = lineColors[key];
        }
        return lineColors;
    },
    colorQueue: function (selectedColor) {
        var colors = {
            0: '#0E6FA4',
            1: '#51BFD8',
            2: '#DA7138',
            3: '#FCA456',
            4: '#2b7b3d',
            5: '#97d37d',
            6: '#CF5030',
            7: '#FFB6C1',
            8: '#6f2f8c',
            9: '#b97dd3',
            10: '#7e0404',
            11: '#BAA0AE',
            12: '#F279BA',
            13: '#993f6c',
            14: '#919191',
            15: '#BFBFBD',
            16: '#ecda3a',
            17: '#b2b200',
            18: '#00d5f2',
            19: '#b2f2fb',
            20: '#0715CD',
            21: '#e8c2f3'
        };
        var selectedKey = GraphHelperMethods.findKey(colors, selectedColor);
        if (parseInt(selectedKey) === 21) {
            selectedKey = -1;
        }
        var nextColor = colors[parseInt(selectedKey) + 1];
        GraphHelperMethods['nextColor'] = nextColor;
    },
    findKey: function (obj, value) {
        var key;
        _.each(obj, function (v, k) {
            if (v === value) {
                key = k;
            }
        });
        return key;
    },
    // findCheckedBoxes: function() {
    //
    // },
    /**
     * this function takes in the color object, colorKeys array, and multiplier to determine how
     * many new colors we need and return and bigger Color object
    **/
    colorMaker: function (colors, colorKeys, multiplier) {
        var i = 23;
        var j = 0;
        while (i < multiplier) {
            colors[i] = colorKeys[j];
            if (j === 21) {
                j = -1;
            }
            j++;
            i++;
        }
        return colors;
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
        if (units.length == 0) {
            return 'n/a';
        }
        if (units.length == 1 && units[0] == "undefined") {
            return 'n/a';
        }
        else if (units.length == 1) {
            return units[0];
        }
        else {
            return "Mixed units";
        }
    },
    /**
     *  This function takes in the unit type for each array and returns the text to display on
     *  the axis
    **/
    createXAxis: function (graphSet, x, svg, type) {
        if (type === 'x') {
            type = "Time";
        }
        else if (type === 'measurement') {
            type = "Measurement";
        }
        else if (type === "name") {
            type = "Line";
        }
        else {
            type = 'Hours';
        }
        var xAxis = graphSet.x_axis(x);
        if (graphSet.x_unit == undefined) {
            graphSet.x_unit = 'n/a';
        }
        svg.append("g")
            .attr("class", "x axis")
            .style("font-size", "12px")
            .attr("transform", "translate(0," + graphSet.height + ")")
            .call(xAxis)
            .append('text')
            .attr("y", 40)
            .attr("x", graphSet.width / 2)
            .style("text-anchor", "middle")
            .text(type);
        //Draw the x Grid lines
        svg.append("g")
            .attr("class", "grid")
            .attr("transform", "translate(0," + graphSet.height + ")")
            .call(xAxis
            .tickSize(-graphSet.height, 0, 0)
            .tickFormat(""));
    },
    /**
     *  This function creates the left y axis svg object
    **/
    createLeftYAxis: function (graphSet, label, y, svg) {
        var yAxis = d3.svg.axis().scale(y)
            .orient("left").ticks(5).tickFormat(d3.format(".2s"));
        if (label === 'undefined') {
            label = 'n/a';
        }
        svg.append("g")
            .attr("class", "y axis")
            .style("font-size", "12px")
            .call(yAxis)
            .append("text")
            .attr('class', 'axis-text')
            .attr("transform", "rotate(-90)")
            .attr("y", -55)
            .attr("x", 0 - (graphSet.height / 2))
            .attr("dy", "1em")
            .style("text-anchor", "middle")
            .text(label);
        // Draw the y Grid lines
        svg.append("g")
            .attr("class", "grid")
            .call(yAxis
            .tickSize(-graphSet.width, 0, 0)
            .tickFormat(""));
    },
    /**
     *  This function creates the right y axis svg object
    **/
    createRightYAxis: function (label, y, svg, spacing) {
        var yAxis = d3.svg.axis().scale(y)
            .orient("right").ticks(5).tickFormat(d3.format(".2s"));
        svg.append("g")
            .attr("class", "y axis")
            .attr("transform", "translate(" + spacing + " ,0)")
            .style("font-size", "12px")
            .style("fill", "black")
            .call(yAxis)
            .append('text')
            .attr("transform", "rotate(-90)")
            .attr('class', 'text')
            .attr('x', -110)
            .attr("dy", ".32em")
            .attr('y', 43)
            .style('text-anchor', 'middle')
            .text(label);
    },
    /**
     *  This function creates the y axis tick marks for grid
    **/
    make_right_y_axis: function (y) {
        return d3.svg.axis()
            .scale(y)
            .orient("left");
        //add ticks here!
    },
    /**
     *  This function creates the x axis tick marks for grid
    **/
    make_x_axis: function (x) {
        return d3.svg.axis()
            .scale(x)
            .orient("bottom");
    }
};
