/**
* this function returns object size  
**/
function objectSize(obj) {

    var size = 0, key;
    for (key in obj) {
        if (obj.hasOwnProperty(key)) size++;
    }
    return size;
};

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

/**
*  This function takes in data and transforms it into the following
*  [
    ...
    [{x, y}, {x, y}, ...],
    [{x, y}, {x, y}, ...],
    ...
    }
**/

function transformBarData(data) {
  var linedata = [] 
  var size = objectSize(data);
  for (var i = 0; i < size; i++) {
    //returns first object 
    var first = (data[Object.keys(data)[i]].values);
    //data 
    var n = [];
    for (var j = 0; j < first.length; j++ ) {
      dataset = {};
      if (first[j][0].length > 0 && first[j][1].length > 0) {
        dataset.x = parseInt(first[j][0].join());
        dataset.y = parseFloat(first[j][1].join());
        dataset.i = i
        n.push(dataset);
         }
       else {
        console.log("missing data for object " + i + " time " + first[j][0])
       }
    }

    linedata.push(n);
  }
      //sort data               
     linedata.forEach(function(d) {
        d.sort(function(a, b) {
          return parseFloat(a.x) - parseFloat(b.x);
        })
      })
    return(linedata);
}

function transformLineData(data) {
  var linedata = [];
  var size = objectSize(data);
  for (var i = 0; i < size; i++) {
    //returns first object 
    var first = (data[Object.keys(data)[i]].values);
    //data 
    var n = [];
    for (var j = 0; j < first.length; j++ ) {
      dataset = {};
      if (first[j][0].length > 0 && first[j][1].length > 0) {
        dataset.x = parseInt(first[j][0].join());
        dataset.y = parseFloat(first[j][1].join());
        dataset.i = i
        n.push(dataset);
         }
       else {
        console.log("missing data for object " + i + " time " + first[j][0])
       }
    }

    linedata.push(n);
  }
      //sort data               
     linedata.forEach(function(d) {
        d.sort(function(a, b) {
          return parseFloat(a.x) - parseFloat(b.x);
        })
      })
    return(linedata);
}
/**
* this function returns an array of y values  
**/
function yvalues(data) {
  var y = [];
  var size = objectSize(data);
  for (var i = 0; i < size; i++) {
    var firstobj = (data[Object.keys(data)[i]].values);
    for (var j = 0; j < firstobj.length; j++) {
      var yval = firstobj[j][1]
      if (yval.length == 1)
      y.push(parseFloat(yval.join()))
    }
  }
  return y;
}

/**
* this function returns an array of x values  
**/
function xvalues(data) {
  var x = [];
  var size = objectSize(data);
  for (var i = 0; i < size; i++) {
    var firstobj = (data[Object.keys(data)[i]].values);
    for (var j = 0; j < firstobj.length; j++) {
      var xval = firstobj[j][0]
      if (xval.length == 1)
      x.push(parseFloat(xval.join()))
    }
  }
  return x;
}

/**
* this function sorts an array of values in ascending order 
**/
 function sortValues(values) {
    values.sort(function(a,b) {
      return parseFloat(b) - parseFloat(a);
    });
    return values
 }

/**
* this function takes in data input and returns an array of labels 
**/

function labels(data) { 
  return Object.keys(data)
}
