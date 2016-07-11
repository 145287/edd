
////// multi bar

/**
* this function takes in input min y value, max y value, and the transformed data. Outputs the graph
**/
function createAssayGraph(linedata, minValue, maxValue, labels, size, arraySize) {

    arraySize = arraySize.pop();
    /**
    * this function creates the x axis tick marks for grid
    **/
    function make_x_axis() {
        return d3.svg.axis()
            .scale(x0)
            .orient("bottom")
            .ticks(5)
    }

    /**
    * this function creates the y axis tick marks for grid
    **/
    function make_y_axis() {
        return d3.svg.axis()
            .scale(y)
            .orient("left")
            .ticks(5)
    }

     var margin = {top: 20, right: 40, bottom: 30, left: 40},
      width = 1000 - margin.left - margin.right,
      height = 270 - margin.top - margin.bottom;

  var colorrange = ["#98abc5", "#8a89a6", "#7b6888", "#6b486b", "#a05d56", "#d0743c", "#ff8c00", "grey"]

    thisColorRange = colorrange.splice(0, labels.length);

    var color = d3.scale.ordinal()
    .range(thisColorRange);

  var x0 = d3.scale.ordinal()
    .domain(d3.range(size))
    .rangeBands([0, width], .1);

  var x1 = d3.scale.ordinal().domain(d3.range(arraySize))
      .rangeBands([0, x0.rangeBand()]);

     var y = d3.scale.linear()
        .range([height, 0]);

     var xAxis = d3.svg.axis()
        .scale(x0)
        .orient("bottom");

     var yAxis = d3.svg.axis()
        .scale(y)
        .orient("left")
        .tickFormat(d3.format(".2s"));

    var svg = d3.select("div#bar")
      .append("svg")
      .attr("preserveAspectRatio", "xMinYMin meet")
      .attr("viewBox", "-30 -40 1100 280")
      .classed("svg-content", true);


 var data = d3.nest()
  .key(function(d) { return d.i; })
  .entries(linedata);

  y.domain([0, d3.max(data, function(d) { return d3.max(d.values, function(d) { return d.y; }); })]);


  svg.append("g")
    .attr("class", "x axis")
    .attr("transform", "translate(0," + height + ")")
    .call(xAxis)

    // Draw the x Grid lines
    svg.append("g")
        .attr("class", "grid")
        .attr("transform", "translate(0," + height + ")")
        .call(make_x_axis()
            .tickSize(-height, 0, 0)
            .tickFormat("")
        )
        // Draw the y Grid lines
    svg.append("g")
        .attr("class", "grid")
        .call(make_y_axis()
            .tickSize(-width, 0, 0)
            .tickFormat("")
        )

  svg.append("g")
      .attr("class", "y axis")
      .call(yAxis)
    .append("text")
      .attr("transform", "rotate(-90)")
      .attr("y", 6)
      .attr("dy", ".71em")
      .style("text-anchor", "end")
      .text("Frequency");

  var c1 = svg.selectAll(".bar")
    .data(data)
    .enter().append('g')
    .attr("class", "bar")
    .attr("transform", function(d) { return "translate(" + x0(d.key) + ",0)"; })

  c1.selectAll("rect")
    .data(function(d) {return d.values})
     .enter().append("rect")
      .attr("width", x1.rangeBand())
      .attr("x", function(d) { return x1(d.x); })
      .attr("y", function(d) { return y(d.y); })
      .attr("height", function(d) { return height - y(d.y); })
      .style("fill", function(d) { return color(d.i); })
    .on("mouseover", function(d) {
        //Get this bar's x/y values, then augment for the tooltip
      var barPos = parseFloat(d3.select(this.parentNode).attr('transform').split("(")[1]);

      var xPosition = barPos + x1(d.x);
      var yPosition = parseFloat(d3.select(this).attr("y"));

        svg.append("text")
          .attr("id", "tooltip")
          .attr("x", xPosition)
          .attr("y", yPosition)
          .attr("text-anchor", "middle")
          .attr("font-family", "sans-serif")
          .attr("font-size", "11px")
          .attr("font-weight", "bold")
          .attr("fill", "black")
          .text(labels[d.i] + ": " + "time: " + d.x + ", value: " + d.y);
      })
      .on("mouseout", function() {
        //Remove the tooltip
        d3.select("#tooltip").remove();

        });

 //legend
 var legend = svg.selectAll(".legend")
      .data(labels)
    .enter().append("g")
      .attr("class", "legend")
     .attr( "transform", function(d,i) {
        var xOff = (i % 4) * 40;
        var yOff = Math.floor(i  / 4) * 10;
        return "translate(" + xOff + "," + yOff + ")"
} );
      // .attr("transform", function(d, i) {
      //     return "translate(0," + i * 20 + ")"; });
      //
  legend.append("rect")
      .attr("x", width + 3)
      .attr("width", 18)
      .attr("height", 10)
      .style("fill", color);

  legend.append("text")
      .attr("x", width)
      .attr("dy", ".35em")
      .style("text-anchor", "end")
      .text(function(d) { return d; })
}
