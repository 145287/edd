
////// multi bar

/**
* this function takes in input min y value, max y value, and the sorted json object.
*  outputs a grouped bar graph with values grouped by assay name
**/
function createAssayGraph(assayMeasurements) {

    var margin = {top: 20, right: 40, bottom: 100, left: 40},
         width = 1000 - margin.left - margin.right,
         height = 270 - margin.top - margin.bottom;

    var color = d3.scale.category10();
    //x axis scale for assay's protein name
    var x_name = d3.scale.ordinal()
        .rangeRoundBands([0, width], .1);
    //x axis scale for x values
    var x_xValue = d3.scale.ordinal();
    //x axis scale for line id to differentiate multiple lines associated with the same protein
    var lineID = d3.scale.ordinal();

    // y axis range scale
    var y = d3.scale.linear()
        .range([height, 0]);

    //x axis scale for protein names
    var protein_axis = d3.svg.axis()
        .scale(x_name)
        .orient("bottom");

    var xValue_axis = d3.svg.axis()
        .scale(x_xValue)
        .orient("bottom");

    var lineID_axis = d3.svg.axis()
        .scale(x_xValue)
        .orient("bottom");

    var yAxis = d3.svg.axis()
        .scale(y)
        .orient("left")
        .tickFormat(d3.format(".2s"));

    var svg = d3.select("div#groupedAssay")
        .append("svg")
        .attr("preserveAspectRatio", "xMinYMin meet")
        .attr("viewBox", "-30 -40 1100 280")
        .classed("svg-content", true)

    //nest data by name. nest again by x label
    var nested = d3.nest()
        .key(function(d) { return d.name; })
        .key(function(d) {return d.x})
        .entries(assayMeasurements);

    /**
    * this function takes in input a protein's line values and inserts a y id key for
    * each x, y object.
    **/
    function addYIdentifier(data3) {
        return _.map(data3, function(d, i) {
            d.key = 'y' + i;
        })
    }

    /**
     *  function takes in nested assayMeasurements and inserts a y id key for each value object
     *  returns data
     */

    //DOUBLE CHECK
    function getXYValues(nested) {
        return _.forEach(nested, function(nameValues) {
            _.map(nameValues, function(xValue){
                addYIdentifier(xValue.values)
            })
        });
        // can I do this? above. return nested
    }

    data = getXYValues(nested);
    var data2 = data.map(function(d) { return (d.values)})
    var proteinNames = data.map(function(d) { return d.key; });
    var names = _.map(proteinNames, function(d, i) {
        return i;
    })
    //returns y0..
    var yvalueIds =  data[0].values[0].values.map(function(d) { return d.key})
    // returns x values
    var xValueLabels = data2[0].map(function(d) { return (d.key)})


    x_name.domain(names);
    x_xValue.domain(xValueLabels).rangeRoundBands([0, x_name.rangeBand()]);
    lineID.domain(yvalueIds).rangeRoundBands([0, x_xValue.rangeBand()]);
    y.domain([0, d3.max(assayMeasurements, function(d) { return d.y})]);

    svg.append("g")
        .attr("class", "x axis")
        .attr("transform", "translate(0," + height + ")")
        .call(protein_axis);

    svg.append("g")
          .attr("class", "y axis")
          .call(yAxis)
        .append("text")
          .attr("transform", "rotate(-90)")
          .attr("y", 6)
          .attr("dy", ".71em")
          .style("text-anchor", "end")
          .text("Frequency");


    var names_g = svg.selectAll(".group")
        .data(data)
        .enter().append("g")
        .attr("class", function(d) {
          return 'group group-' + d.key;  //returns assay names
        })
        .attr("transform", function(d) {
          return "translate(" + x_name(d.key) + ",0)";
        });

    var categories_g = names_g.selectAll(".category")
        .data(function(d) {
          return d.values;  // values = [0, 12, 15, 18, 23, 36, 45, 60]
        })
        .enter().append("g")
        .attr("class", function(d) {
          return 'category category-' + d.key;   // returns objects with key = value
        })
        .attr("transform", function(d) {
          return "translate(" + x_xValue(d.key) + ",0)";
        });

    var categories_labels = categories_g.selectAll('.category-label')
        .data(function(d) {
          return [d.key]; // returns ["0"]
        })
        .enter()
        .append("text")
        .attr("class", function(d) {
          return 'category-label category-label-' + d;   //returns 0 - 64...
        })
        .attr("x", function(d) {
          return x_xValue.rangeBand() / 2;
        })
        .attr('y', function(d) {
          return height + 25;
        })
        .attr('text-anchor', 'middle')
        .text(function(d) {
              return d;
            })
        .style("font-size", 8)


    var values_g = categories_g.selectAll(".value")
        .data(function(d) {
          return d.values;
        })
        .enter().append("g")
        .attr("class", function(d) {
          return 'value value-' + d.i;
        })
        .attr("transform", function(d) {
          return "translate(" + lineID(d.key) + ",0)";
        });

    var values_labels = values_g.selectAll('.value-label')
        .data(function(d) {
         return [d.key]; //["y0"]
        })
        .enter().append("text")
        .attr("class", function(d) {
          return 'value-label value-label-' + d;
        })
        .attr("x", function(d) {
          return lineID.rangeBand() / 2;
        })
        .attr('y', function(d) {
          return height + 10;
        })
        .attr('text-anchor', 'middle');

    var rects = values_g.selectAll('.rect')
        .data(function(d) {
          return [d]; // returns [{i:, x:, y:, ...}]
        })
        .enter().append("rect")
        .attr("class", "rect")
        .attr("width", lineID.rangeBand())
        .attr("y", function(d) {
          return y(d.y);
        })
        .attr("height", function(d) {
          return height - y(d.y);
        })
        .style("fill", function(d) {
            return color(d.key)
        })
        .style("opacity", 0.3);

    //
    var hover = categories_g.selectAll('.rect')
        .data(function(d) {
            return d.values  // returns [{i:, x:, y:, ...}]
        })
        .on("mouseover", function() { tooltip.style("display", null); })
        .on("mouseout", function() { tooltip.style("display", "none"); })
        .on("mousemove", function(d) {
            var barPos = parseFloat(d3.select(this.parentNode).attr('transform').split("(")[1]);
            var xPosition = barPos + d3.mouse(this)[0] - 15;
            var yPosition = d3.mouse(this)[1] - 25;
            tooltip.attr("transform", "translate(" + xPosition + "," + yPosition + ")");
            tooltip.select("text").html(d.y + " " + d.y_unit)
        });

        //tooltip
    var tooltip = svg.append("g")
      .attr("class", "tooltip")
      .style("display", "none");

    tooltip.append("rect")
      .attr("width", 100)
      .attr("height", 20)
      .attr("fill", "white")
      .style("opacity", 0.5);

    tooltip.append("text")
      .attr("x", 50)
      .attr("dy", "1.2em")
      .style("text-anchor", "middle")
      .attr("font-size", "12px")
      .attr("font-weight", "bold");
}
