/**
* this function creates the line graph 
**/
function createLineGraph(assayMeasurements) {

    //get x values
    var xDomain = assayMeasurements.map(function(d) { return d.x; })

    //sort x values
    xDomain.sort(function(a, b) {
        return a - b
    });

    var div = d3.select("body").append("div")
        .attr("class", "tooltip2")
        .style("opacity", 0);

    var margin = {top: 20, right: 150, bottom: 30, left: 40},
        width = 1000 - margin.left - margin.right,
        height = 270 - margin.top - margin.bottom;

    var color = d3.scale.category10();

    var y = d3.scale.linear().range([height, 0]);
    var x = d3.scale.linear().domain([xDomain[0] - 1, xDomain[xDomain.length -1]]).range([0, width]);


    var yAxis = d3.svg.axis()
        .scale(y)
        .orient("left")
        .tickFormat(d3.format(".2s"));

    var xAxis = d3.svg.axis()
        .scale(x)
        .orient("bottom")
        .ticks(5);

    //create svg graph object
    var svg = d3.select("div#linechart").append("svg")
        .attr("preserveAspectRatio", "xMinYMin meet")
        .attr("viewBox", "-30 -40 1100 280")
        .classed("svg-content", true);

    svg.append("g")
        .attr("class", "x axis")
        .attr("transform", "translate(0," + height + ")")
        .call(xAxis);


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

    var lineGen = d3.svg.line()
        .x(function (d) {
            return x(d.x);
        })
        .y(function (d) {
            return y(d.y)
        });

    y.domain([0, d3.max(assayMeasurements, function(d) { return d.y})]);

    //iterate through different arrays. right now i is undefined.. not sure what is happening. 
    var data = d3.nest()
        .key(function (d) {
            return d.name;
        })
        .key(function (d) {
            return d.i;
        })
        .entries(assayMeasurements);
    
    var proteinNames = d3.nest()
        .key(function (d) {
            return d.name;
        })
        .entries(assayMeasurements);
    var names = proteinNames.map(function (d) {return d.key;})


    for (var k = 0; k < data.length; k++) {
        var color1 = color(data[k].key)
        //label name coincides with same color
        //lines
        for (var j = 0; j < data[k].values.length; j++) {
            var line = svg.append('path')
                .attr("id", data[k].key.split(' ').join('_'))
                .attr('d', lineGen(data[k].values[j].values))
                .attr('stroke', color1)
                .attr('stroke-width', 2)
                .attr("class", "experiment")
                .attr('fill', 'none');
        var dataCirclesGroup = svg.append('svg:g');
        var circles = dataCirclesGroup.selectAll('.data-point')
            .data(data[k].values[j].values);
        circles
            .enter()
            .append('svg:circle')
            .attr('class', 'dot')
            //.attr('id', ("circle" + data[k].key).split(' ').join('_') )
            .attr('fill', 'grey')
            .attr('cx', function (d) {
                return x(d["x"]);
            })
            .attr('cy', function (d) {
                return y(d["y"]);
            })
            .attr('r', function () {
                return 3;
            })
            .style("fill", color1)
            .on("mouseover", function (d) {
                div.transition()
                    .duration(200)
                    .style("opacity", .9);
                div.html('<strong>' + d.name + '</strong>' + ": " + d.y + " " + d.y_unit)
                    .style("left", (d3.event.pageX) + "px")
                    .style("top", (d3.event.pageY - 30) + "px");
            })
            .on("mouseout", function (d) {
                div.transition()
                    .duration(500)
                    .style("opacity", 0);
            });
        }

        var legend = svg.selectAll(".legend")
                  .data(data)
                  .enter().append("g")
                  .attr("class", "legend")
                  .attr("transform", function(d, i) {
                    return "translate(0," + i * 20 + ")";
                  });

                legend.append("rect")
                  .attr("x", width + 5)
                  .attr("width", 18)
                  .attr("height", 18)
                  .style("fill", function (d) { // Add the colours dynamically
                    return data.color = color(d.key);
                 })

                legend.append("text")
                  .attr("x", width + 25)
                  .attr("y", 9)
                  .attr("dy", ".35em")
                  .style("text-anchor", "start")
                  .text(function(d) {
                    return d.key;
                  })
        //hide legend for too many entries. 
        if (names.length > 10) {
            d3.selectAll(".legend").style("display", "none");
        }   
    }
        /**
     * this function creates the x axis tick marks for grid
     **/
    function make_x_axis() {
        return d3.svg.axis()
            .scale(x)
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
}
