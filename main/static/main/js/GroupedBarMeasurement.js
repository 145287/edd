/**
 * this function takes in input min y value, max y value, and the sorted json object.
 *  outputs a grouped bar graph with values grouped by assay name
 **/
 function createGroupedBarGraph(graphSet, svg, type) {

    //different svg 
    var typeClass = {
        'measurement': ".groupedMeasurement",
        'x': ".timeBar",
        'name': '.groupedAssay'
    };

    var assayMeasurements = graphSet.assayMeasurements,
        numUnits = howManyUnits(assayMeasurements),
        yRange = [],
        unitMeasurementData = [],
        yMin = [];

    //x axis scale for type
    var x_name = d3.scale.ordinal()
        .rangeRoundBands([0, graphSet.width], 0.1);
    
    //x axis scale for x values
    var x_xValue = d3.scale.ordinal();
    
    //x axis scale for line id to differentiate multiple lines associated with the same name/type
    var lineID = d3.scale.ordinal();

    // y axis range scale
    var y = d3.scale.linear()
        .range([graphSet.height, 0]);
    
    var div = d3.select("body").append("div")
        .attr("class", "tooltip2")
        .style("opacity", 0);
    
    var meas = d3.nest()
        .key(function (d) {
            return d.y_unit;
        })
        .entries(assayMeasurements);

    for (var i = 0; i < numUnits; i++) {
        yRange.push(d3.scale.linear().rangeRound([graphSet.height, 0]));
        unitMeasurementData.push(d3.nest()
            .key(function (d) {
                return d.y;
            })
            .entries(meas[i].values));
        yMin.push(d3.min(unitMeasurementData[i], function (d) {
        return d3.min(d.values, function (d) {
            return d.y;
        });
    }))
    }

    // nest data by type (ie measurement) and by x value
    var nested = d3.nest(type)
            .key(function (d) {
                return d[type];
            })
            .key(function (d) {
                return parseFloat(d.x);
            })
            .entries(assayMeasurements);

    //insert y value to distinguish between lines
    var data = getXYValues(nested);

    //get type names for x labels
    var typeNames = data.map(function (d) {
            return d.key;
        });

    //sort x values
    typeNames.sort(function (a, b) {
            return a - b
        });

    var xValues = data.map(function (d) {
        return (d.values);
    });

    var yvalueIds = data[0].values[0].values.map(function (d) {
        return d.key;
    });

    // returns time values
    var xValueLabels = xValues[0].map(function (d) {
        return (d.key);
    });

    //sort time values
    var sortedXvalues = xValueLabels.sort(function(a, b) { return parseFloat(a) - parseFloat(b)});

    x_name.domain(typeNames);

    x_xValue.domain(sortedXvalues).rangeRoundBands([0, x_name.rangeBand()]);

    lineID.domain(yvalueIds).rangeRoundBands([0, x_xValue.rangeBand()]);
    
    //create x axis
    graphSet.create_x_axis(graphSet, x_name, svg, type);

    //loop through different units
    for (var index = 0; index<numUnits; index++) {

        if (yMin[index] > 0 ) {
            yMin[index] = 0;
        }
        //y axis min and max domain 
        y.domain([yMin[index], d3.max(unitMeasurementData[index], function (d) {
            return d3.max(d.values, function (d) {
                return d.y;
            });
        })]);

        //nest data associated with one unit by type and time value
        data = d3.nest(type)
            .key(function (d) {
                return d[type];
            })
            .key(function (d) {
                return parseFloat(d.x);
            })
            .entries(meas[index].values);

        //right axis
        if (index == 0) {
            graphSet.create_y_axis(graphSet, meas[index].key, y, svg);
        } else {
            var spacing = {
                1: graphSet.width,
                2: graphSet.width + 50,
                3: graphSet.width + 100,
                4: graphSet.width + 150
            };
            //create right axis
            graphSet.create_right_y_axis(meas[index].key, y, svg, spacing[index])
        }

        //see how long the label is
        var labelLength = data.length;
        
        var names_g = names_g +  index,
            categories_g = categories_g  + index,
            categories_labels = categories_labels  + index,
            values_g = values_g  + index,
            rects = rects  + index,

        names_g = svg.selectAll(".group" + index)
            .data(data)
            .enter().append("g")
            .attr("class", 'truncate')
            .attr("transform", function (d) {
                return "translate(" + x_name(d.key) + ",0)";
            });

        categories_g = names_g.selectAll(".category" + index)
            .data(function (d) {
                return d.values;
            })
            .enter().append("g")
            .attr("class", "truncate")
            .attr("transform", function (d) {
                return "translate(" + x_xValue(d.key) + ",0)";
            });

        categories_labels = categories_g.selectAll('.category-label' + index)
            .data(function (d) {
                return [d.key];
            })
            .enter()
            .append("text")
            .attr("class", "truncate")
            .attr("x", function () {
                return x_xValue.rangeBand() / 2;
            })
            .attr('y', function () {
                return graphSet.height + 27;
            })
            .attr('text-anchor', 'middle')

        values_g = categories_g.selectAll(".value" + index)
            .data(function (d) {
                return d.values;
            })
            .enter().append("g")
            .attr("class", function (d) {
                return 'value value-' + d.i;
            })
            .attr("transform", function (d) {
                return "translate(" + lineID(d.key) + ",0)";
            });

        rects = values_g.selectAll('.rect' + index)
            .data(function (d) {
                return [d];
            })
            .enter().append("rect")
            .attr("class", "rect")
            .attr("width", lineID.rangeBand())
            .attr("y", function (d) {
                return y(d.y);
            })
            .attr("height", function (d) {
                return graphSet.height - y(d.y);
            })
            .style("fill", function (d) {
                return d.color
            })
            .style("opacity", 0.3);

        var hover = categories_g.selectAll('.rect')
            .data(function (d) {
                return d.values;
            })
            .on("mouseover", function (d) {
                div.transition()
                    .style("opacity", 0.9);
                div.html("<strong>" + d.name + "</strong></br>" + d.y + ": " + d.y_unit + "</br>" + d.x
                    + ":  hours" + "</br>" + "measurement: " + d.measurement)
                    .style("left", (d3.event.pageX) + "px")
                    .style("top", (d3.event.pageY - 28) + "px");
            })
            .on("mouseout", function () {
                div.transition()
                    .style("opacity", 0);
            });

        //get word length
        var wordLength = getSum(typeNames);

        if (wordLength > 90 && type != 'x') {
           d3.selectAll(typeClass[type] + ' .x.axis text').remove()
        }
        if (wordLength > 150 && type === 'x') {
           d3.selectAll(typeClass[type] + ' .x.axis text').remove()
        }
    }
}