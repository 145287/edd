/// <reference path="typescript-declarations.d.ts" />


// This file contains various utility classes under the Utl module.

module Utl {

	export class EDD {

		static resolveMeasurementRecordToName(measurementRecord:AssayMeasurementRecord):string {

			var mName = '';
			// We figure out the name and units differently based on the subtype.
			var mst = measurementRecord.mst;
			if (mst == 1) {	// Metabolite type.  Magic numbers.  EW!  TODO: Eeeew!
				var compName = '';
				var compID = measurementRecord.mq;
				if (compID) {
					var cRecord = EDDData.MeasurementTypeCompartments[compID];
					if (cRecord) {
						compName = cRecord.sn + ' ';
					}
				}
            	var mRecord = EDDData.MetaboliteTypes[measurementRecord.mt];
            	mName = compName + mRecord.name;
		    } else if (mst == 2) {	// Gene type.  EWW EWW
            	mName = EDDData.GeneTypes[measurementRecord.mt].name;
		    } else if (mst == 3) {	// Protein type.  EWW EWW
            	mName = EDDData.ProteinTypes[measurementRecord.mt].name;
		    }
		    return mName;
		}


		static resolveMeasurementRecordToUnits(measurementRecord:AssayMeasurementRecord):string {

			var mUnits = '';
			var mst = measurementRecord.mst;
			if (mst == 1) {		// TODO: https://www.youtube.com/watch?v=JltEXpbGM8s
            	if (measurementRecord.uid) {
	            	var uRecord = EDDData.UnitTypes[measurementRecord.uid];
	            	if (uRecord) {
	            		mUnits = uRecord.name;
	            	}
		        }
		    } else if (mst == 2) {
            	mUnits = '';	// Units for Proteomics?  Anyone?
		    } else if (mst == 3) {
            	mUnits = 'RPKM';
		    }
		    return mUnits;
		}
	}


	export class QtipHelper {
		public create(linkElement, contentFunction, params:any):void {

			params.position.target = $(linkElement);
			params.position.viewport = $(window);	// This makes it position itself to fit inside the browser window.

			this._contentFunction = contentFunction;

			if (!params.content)
				params.content = {};

			params.content.text = this._generateContent.bind(this);
			this.qtip = $(linkElement).qtip(params);
		}

		private _generateContent():any {
			// It's incredibly stupid that we have to do this to work around qtip2's 280px max-width default.
			// We have to do it here rather than immediately after calling qtip() because qtip waits to create
			// the actual element.
			var q = this._getQTipElement();
			$(q).css('max-width', 'none');
			$(q).css('width', 'auto');

			return this._contentFunction();
		}

		// Get the HTML element for the qtip. Usually we use this to unset max-width.
		private _getQTipElement():HTMLElement {
			return document.getElementById(this.qtip.attr('aria-describedby'));
		}

		public qtip:any;
		private _contentFunction:any;
	}


	// RGBA helper class.
	// Values are 0-255 (although toString() makes alpha 0-1 since that's how CSS likes it).
	export class Color {

		r: number;
		g: number;
		b: number;
		a: number;

		// Note: All values are 0-255, but toString() will convert alpha to a 0-1 value
		static rgba(r:number, g:number, b:number, alpha:number) : Color {
			var clr:Color = new Color();
			clr.r = r;
			clr.g = g;
			clr.b = b;
			clr.a = alpha;
			return clr;
		}

		// Note: All values are 0-255, but toString() will convert alpha to a 0-1 value
		static rgb(r:number, g:number, b:number) : Color {
			var clr:Color = new Color();
			clr.r = r;
			clr.g = g;
			clr.b = b;
			clr.a = 255;
			return clr;
		}

		static interpolate(clr1:Color, clr2:Color, t:number) : Color {
			return Color.rgba(
				clr1.r + (clr2.r - clr1.r) * t, 
				clr1.g + (clr2.g - clr1.g) * t, 
				clr1.b + (clr2.b - clr1.b) * t, 
				clr1.a + (clr2.a - clr1.a) * t
			);
		}

		static toString(clr:any) : string {
			// If it's something else (like a string) already, just return that value.
			if (typeof clr == 'string')
				return clr;

			return 'rgba(' + Math.floor(clr.r) + ', ' + Math.floor(clr.g) + ', ' + Math.floor(clr.b) + ', ' + clr.a/255 + ')';
		}

		toString() : string {
			return 'rgba(' + Math.floor(this.r) + ', ' + Math.floor(this.g) + ', ' + Math.floor(this.b) + ', ' + this.a/255 + ')';
		}

		static red = Color.rgb(255,0,0);
		static green = Color.rgb(0,255,0);
		static blue = Color.rgb(0,0,255);
		static black = Color.rgb(0,0,0);
		static white = Color.rgb(255,255,255);

	};


	export class Table {

		constructor(tableID:string, width?:number, height?:number) {
			this.table = document.createElement('table');
			this.table.id = tableID;

			if (width)
				$(this.table).css('width', width);

			if (height)
				$(this.table).css('height', height);
		}

		addRow():HTMLTableRowElement {
			var row = this.table.insertRow(-1);
			this._currentRow++;
			return <HTMLTableRowElement>row;
		}

		addColumn():HTMLElement {
			var row:HTMLTableRowElement = <HTMLTableRowElement>this.table.rows[this._currentRow-1];
			var column:HTMLElement = row.insertCell(-1);
			return column;
		}

		// When you're done setting up the table, add it to another element.
		addTableTo(element:HTMLElement) {
			element.appendChild(this.table);
		}

		table:HTMLTableElement = null;
		_currentRow:number = 0;
	}


	// Javascript utilities
	export class JS {

		// This assumes that str has only one root element.
		// It also breaks for elements that need to be nested under other specific element types,
		// e.g. if you attempt to create a <td> you will be handed back a <div>.
		static createElementFromString(str:string, namespace:string = null):HTMLElement {

			var div;
			if (namespace)
				div = document.createElementNS(namespace, 'div');
			else
				div = document.createElement('div');

			div.innerHTML = str;
			return div.firstChild;

		}


		static assert(condition:boolean, message:string):void {
		    if (!condition) {
                message = message || "Assertion failed";
                if (typeof Error !== 'undefined') throw Error(message);
                else throw message;
		    }
		}

		
		static convertHashToList(hash:any):any {
			return Object.keys(hash).map( function(a) {return hash[a];} );
		}


		// Returns a string of length numChars, padding the right side
		// with spaces if str is shorter than numChars.
		// Will truncate if the string is longer than numChars.
		static padStringLeft(str:string, numChars:number):string {
			var startLen:number = str.length;
			for (var i=startLen; i < numChars; i++)
				str += ' ';

			return str.slice(0, numChars);
		}


		// Returns a string of length numChars, padding the left side
		// with spaces if str is shorter than numChars.
		static padStringRight(str:string, numChars:number):string {
			var padStr = "";
			for (var i=0; i < numChars; i++)
				padStr += " ";

			return (padStr + str).slice(-numChars);
		}


		// Make a string by repeating the specified string N times.
		static repeatString(str:string, numChars:number):string {
			var ret:string = "";
			for (var i:number=0; i < numChars; i++)
				ret += str;

			return ret;
		}


		// Convert a size provided in bytes to a nicely formatted string
		static sizeToString(size:number, allowBytes?:boolean):string {

			var tb = size / (1024 * 1024 * 1024 * 1024);
			if ((tb > 1) || (tb < -1)) {
				return Utl.JS.nicelyPrintFloat(tb, 2) + ' Tb';
			}
			var gigs = size / (1024 * 1024 * 1024);
			if ((gigs > 1) || (gigs < -1)) {
				return Utl.JS.nicelyPrintFloat(gigs, 2) + ' Gb';
			}
			var megs = size / (1024 * 1024);
			if ((megs > 1) || (megs < -1)) {
				return Utl.JS.nicelyPrintFloat(megs, 2) + ' Mb';
			}
			var k = size / 1024;
			if (((k > 1) || (k < -1)) || !allowBytes) {
				return Utl.JS.nicelyPrintFloat(k, 2) + ' Kb';
			}
			return size + ' b';
		}


		// -1 : Print as a full float
		//  0 : Print as an int, ALWAYS rounded down.
		// +n : Print with n decimal places, UNLESS the value is an integer
		static nicelyPrintFloat(v:number, places:number):string {
			// We do not want to display ANY decimal point if the value is an integer.
			if (v % 1 === 0) {	// Basic integer test
				return (v % 1).toString();
			}
			if (places > 0) {
				return v.toFixed(places);
			} else if (places == 0) {
				return (v % 1).toString();
			}
			return v.toString();
		}


		// Given a file name (n) and a file type string (t), try and guess what kind of file we've got.
		static guessFileType(n: string, t: string): string {
			// Going in order from most confident to least confident guesses:
			if (t.indexOf('officedocument.spreadsheet') >= 0) { return 'excel'; }
			if (t === 'text/csv') { return 'csv'; }
			if (t === 'text/xml') { return 'xml'; }
			if ((n.indexOf('.xlsx', n.length - 5) !== -1) || (n.indexOf('.xls', n.length - 4) !== -1)) { return 'excel'; }
			if (n.indexOf('.xml', n.length - 4) !== -1) { return 'xml'; }
			// If all else fails, assume it's a csv file.  (So, any extension that's not tried above, or no extension.)
			return 'csv';
		}


		// Given a date in seconds (with a possible fractional portion being milliseconds),
		// based on zero being midnight of Jan 1, 1970 (standard old-school POSIX time),
		// return a string formatted in the manner of "Dec 21 2012, 11:45am",
		// with exceptions for 'Today' and 'Yesterday', e.g. "Yesterday, 3:12pm".
		static timestampToTodayString(timestamp:number):string {

			// Code adapted from Perl's HTTP-Date
			//var DoW = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
			var MoY = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

			if (!timestamp || timestamp < 1) {
				return '<span style="color:#888;">N/A</span>';
			}

			var t = new Date(Math.round(timestamp*1000));
			var n = new Date();
			var now = n.getTime();

			var sec = t.getSeconds();
			var min:any = t.getMinutes();	// Type "any" so we can add a leading zero
			var hour = t.getHours();
			var mday = t.getDate();		// Returns the day of the month (from 1-31)
			var mon = t.getMonth();		// Returns the month (from 0-11)
			var year = t.getFullYear();	// Returns the year (four digits)
			var wday = t.getDay();		// Returns the day of the week (from 0-6)

			var nsec = n.getSeconds();
			var nmin = n.getMinutes();
			var nhour = n.getHours();
			var nmday = n.getDate();
			var nmon = n.getMonth();
			var nyear = n.getFullYear();
			var nwday = n.getDay();

			var day_str;

			if ((year == nyear) && (mon == nmon) && (mday == nmday)) {
				day_str = 'Today';
			} else if (	    (now - (nsec + (60*(nmin+(60*(nhour+24)))))) ==		// Now's day component minus a day
					  (timestamp - (sec  + (60*(min +(60* hour     ))))))	 {	// Timestamp's day component
				day_str = 'Yesterday';
			} else {
				var year_str = '';
				if (year != nyear) {
					year_str = ' ' + year;
				}
				day_str = MoY[mon] + ' ' + mday + year_str;
			}

			var half_day = 'am';
			if (hour > 11) {half_day = 'pm';}
			if (hour > 12) {hour -= 12;}
			else if (hour == 0) {hour = 12;}
			if (min < 9) {min = '0'+min;}

			return day_str + ', ' + hour + ':' + min + half_day;
		}


        static utcToTodayString(utc:string):string {
            var m:any[];
            var timestamp:number;
            m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.?(\d{1,6})?Z$/.exec(utc);
            if (m) {
                m.shift(); // get rid of overall match, we don't care
                m.map((v) => { return parseInt(v, 10); }); // convert strings to numbers
                m[1]--; // Date uses 0-based months, so decrement month
                timestamp = Date.UTC(m[0], m[1], m[2], m[3], m[4], m[5]);
                timestamp /= 1000; // the timestampToTodayString expects seconds, not milliseconds
                return Utl.JS.timestampToTodayString(timestamp);
            }
            return Utl.JS.timestampToTodayString(null);
        }


		// Remap a value from [inMin, inMax] to [outMin, outMax]
		static remapValue(value:number, inMin:number, inMax:number, outMin:number, outMax:number):number {
			var delta:number = inMax - inMin;

			// If they've given us a tiny input range, then we can't really parameterize
			// into the range, so let's just return halfway between the outputs.
			if (Math.abs(delta) < 0.000001)
				return outMin + (outMax - outMin) * 0.5;

			var t = (value - inMin) / (inMax - inMin);
			return outMin + (outMax - outMin) * t;
		}

		// Remove all child elements from the specified element.
		static removeAllChildren(element: HTMLElement): void {
			while (element.firstChild)
				element.removeChild(element.firstChild);
		}

		static removeFromParent(element: HTMLElement): void {
			if (element && element.parentNode)
				element.parentNode.removeChild(element);
		}

		// Call this anywhere in your code to trap F12 keypress to stop in debugger.
		// This is useful for looking at DOM elements in a popup that would normally go away when
		// you moved the mouse away from it.
		static enableF12Trap(): void {
			$(window).keydown(function(e) { if (e.keyCode == 123) debugger; });
		}

		static startWaitBadge(selector): void {
			$(selector).css("class", "waitbadge wait");
		}

		static stopWaitBadge(selector): void {
			$(selector).css("class", "waitbadge");
		}
	}



	// A progress bar with a range from 0 to 100 percent.
	// When given only an id, the class seeks an element in the document and uses that as the progress bar.
	// When given a parent element, the class makes a new <progress> element underneath it with the given id.
	export class ProgressBar {

		element: HTMLElement;


		constructor(id: string, parentElement?: HTMLElement) {
			var b: HTMLElement;
			if (parentElement) {
				b = $('<progress>').appendTo(parentElement)[0];
				b.id = id;
			} else {
				b = document.getElementById(id);
			}
			b.innerHTML = '0% complete';
			b.setAttribute('min', '0');
			b.setAttribute('max', '100');
			b.setAttribute('value', '0');
			b.className = 'off';
			this.element = b;
		}


		// Sets the progress bar from 0 to 100 percent, or no value to disable.
		// Also shows the spinny wait icon if the progress bar is set to a value other than 100.
		setProgress(percentage?: number) {
			var b = this.element;
			if (typeof (percentage) === 'undefined') {
				b.innerHTML = '0% complete';
				b.setAttribute('value', '0');
				b.className = 'off';
			} else {
				b.innerHTML = percentage + '% complete';
				b.setAttribute('value', percentage.toString());
				b.className = '';
			}
		}
	}



	// Used by FileDropZone to pass around additional info for each dropped File object without
	// messing with the filedrop-min.js internals.
    interface FileDropZoneFileContainer {
        file: any;					// The file object as created by filedrop-min.js
        fileType: string;			// A guess at the file's type, expressed as a string, as returned by Utl.JS.guessFileType .
        progressBar: ProgressBar;	// The ProgressBar object used to track this file.  Can be altered after init by fileInitFn.

        stopProcessing: boolean;	// If set, abandon any further action on the file.
        skipProcessRaw: boolean;	// If set, skip the call to process the dropped file locally.
        skipUpload: boolean;		// If set, skip the upload to the server (and subsequent call to processResponseFn)
        allWorkFinished: boolean;	// If set, the file has finished all processing by the FileDropZone class.

        // This is assigned by FileDropZone when the object is generated, and can be used to correlate the
        // object with other information elsewhere.  (It is not used internally by FileDropZone.)
        uniqueIndex: number;
    }



	// A class wrapping filedrop-min.js (http://filedropjs.org) and providing some additional structure.
	// It's initialized with a single 'options' object:
	// {
	//	elementId: ID of the element to be set up as a drop zone
	//	fileInitFn: Called when a file has been dropped, but before any processing has started
	//	processRawFn: Called when the file content has been read into a local variable, but before any communication with
	//                the server.
	//	url: The URL to upload the file.
	//	progressBar: A ProgressBar object for tracking the upload progress.
	//	processResponseFn: Called when the server sends back its results.
	// }
	// All callbacks are given a FileDropZoneFileContainer object as their first argument.

	// TODO:
	// * Rewrite this with an option to only accept the first file in a dropped set.
	// * Create a fileContainerGroup object, and a fileContainergGroupIndexCounter, and assign sets of files the same group UID.
	// * Add a 'cleanup' callback that's called after all files in a group have been uploaded.
	export class FileDropZone {

		zone: any;
		csrftoken: any;
		elementId: any;
		url: string;
		progressBar: ProgressBar;

		fileInitFn: any;
		processRawFn: any;
		processResponseFn: any;

		static fileContainerIndexCounter: number = 0;

		// If processRawFn is provided, it will be called with the raw file data from the drop zone.
		// If url is provided and processRawFn returns false (or was not provided) the file will be sent to the given url.
		// If processResponseFn is provided, it will be called with the returned result of the url call.
        constructor(options:any) {

			this.progressBar = options.progressBar || null;

			// If there's a cleaner way to force-disable event logging in filedrop-min.js, do please put it here!
			(<any>window).fd.logging = false;

			var z = new FileDrop(options.elementId, {});	// filedrop-min.js , http://filedropjs.org
			this.zone = z;
			this.csrftoken = jQuery.cookie('csrftoken');
			if (!(typeof options.multiple === "undefined")) {
				z.multiple(options.multiple);
			} else {
				z.multiple(false);
			}
			this.fileInitFn = options.fileInitFn;
			this.processRawFn = options.processRawFn;
			this.processResponseFn = options.processResponseFn;
			this.url = options.url;
		}


		// Helper function to create and set up a FileDropZone.
		static create(options:any): void {
			var h = new FileDropZone(options);
			h.setup();
		}


		setup():void {
			var t = this;
			this.zone.event('send', function(files) {
				files.each(function(file) {

					var fileContainer:FileDropZoneFileContainer  = {
						file: file,
						fileType: Utl.JS.guessFileType(file.name, file.type),
						progressBar: t.progressBar,
						uniqueIndex: FileDropZone.fileContainerIndexCounter++,
						stopProcessing: false,
						skipProcessRaw: null,
						skipUpload: null,
						allWorkFinished: false
					}

					// callInitFile may set fileContainer's internal stopProcessing flag, or any of the others.
					// So it's possible for callInitFile to act as a gatekeeper, rejecting the dropped file
					// and halting any additional processing, or it can decide whether to read and process
					// this file locally, or upload it to the server, or even both.
					// Another trick: callInitFile may swap in a custom ProgressBar object just for this file,
					// so multiple files can have their own separate progress bars, while they are all uploaded
					// in parallel.
					t.callInitFile.call(t, fileContainer);
					if (fileContainer.stopProcessing) { fileContainer.allWorkFinished = true; return; }

					t.callProcessRaw.call(t, fileContainer);
				});
			});
		}


		// If there is a fileInitFn set, call it with the given FileDropZoneFileContainer.
		callInitFile(fileContainer: FileDropZoneFileContainer) {
			if (typeof this.fileInitFn === "function") {
				this.fileInitFn(fileContainer);
			}
		}


		// If processRawFn is defined, we read the entire file into a variable,
		// then pass that to processRawFn along with the FileDropZoneFileContainer object.
		// FileDropZoneFileContainer's contents might be modofied - specifically, the flags - so we check them afterwards
		// to decide how to proceed.
		callProcessRaw(fileContainer: FileDropZoneFileContainer) {
			var t = this;
			if (typeof this.processRawFn === "function" && !fileContainer.skipProcessRaw) {
				fileContainer.file.read({
					//start: 5,
					//end: -10,
					//func: 'cp1251',
					onDone: function(str) {
						t.processRawFn(fileContainer, str);
						if (!fileContainer.stopProcessing && !fileContainer.skipUpload) {
							t.uploadFile.call(t, fileContainer);
						} else {
							fileContainer.allWorkFinished = true;
						}
					},
					onError: function(e) {
						alert('Failed to read the file! Error: ' + e.fdError)
					},
					func: 'text'
				})
			// No need to check stopProcessing - there's no way it could have been modified since the last step.
			} else if (!fileContainer.skipUpload) {
				this.uploadFile(fileContainer);
			}
		}


		uploadFile(fileContainer: FileDropZoneFileContainer) {

			var t = this;
			var f = fileContainer.file;
			// If no url has been defined, we have to stop here.
			if (typeof this.url !== 'string') { fileContainer.allWorkFinished = true; return; }

			// From this point on we assume we're uploading the file,
			// so we set up the progressBar and callback events before triggering the call to upload.
			f.event('done', function(xhr) {
				var result = jQuery.parseJSON(xhr.responseText);
				if (result.python_error) {
					alert(result.python_error);	// TODO: This is a bit extreme. Might want to just pass it to the callback.
				} else if (typeof t.processResponseFn === "function") {
					t.processResponseFn(fileContainer, result);
				}
				fileContainer.allWorkFinished = true;
			});

			f.event('error', function(e, xhr) {
				// TODO: Again, heavy handed. Might want to just embed this in FileDropZoneFileContainer
				// and make an error handler callback.
				alert('Error uploading ' + f.name + ': ' + xhr.status + ', ' + xhr.statusText);
				fileContainer.allWorkFinished = true;
			});

			f.event('xhrSetup', function(xhr) {
				// This ensures that the CSRF middleware in Django doesn't reject our HTTP request.
				xhr.setRequestHeader("X-CSRFToken", t.csrftoken);
				// We want to pass along our own guess at the file type, since it's based on a more specific set of criteria.
				xhr.setRequestHeader('X-EDD-File-Type', fileContainer.fileType)
			});

			f.event('sendXHR', function() {
				if (fileContainer.progressBar) {
					fileContainer.progressBar.setProgress(0);
				}
			})

			// Update progress when browser reports it:
			f.event('progress', function(current, total) {
				if (fileContainer.progressBar) {
					var width = current / total * 100;
					fileContainer.progressBar.setProgress(width);
				}
			})

			f.sendTo(this.url);
		}
	}



	// SVG-related utilities.
	export class SVG {

		static createSVG(width:any, height:any, boxWidth:number, boxHeight:number):SVGElement {
			var svgElement:SVGElement = <SVGElement>document.createElementNS(SVG._namespace, "svg");
			svgElement.setAttribute('version', '1.2');
			svgElement.setAttribute('width', width.toString());
			svgElement.setAttribute('height', height.toString());
			svgElement.setAttribute('viewBox', '0 0 ' + boxWidth + ' ' + boxHeight);
			svgElement.setAttribute('preserveAspectRatio', 'none');
			return svgElement;
		}


		// Creates a vertical line centered on (xCoord,yCoord).
		static createVerticalLinePath(xCoord:number, yCoord:number, lineWidth:number, lineHeight:number, color:Color, svgElement:any):SVGElement {
			var halfWidth:number = lineWidth / 2;

			var topY:number = Math.floor(yCoord - lineHeight/2);
			var bottomY:number = Math.floor(yCoord + lineHeight/2);
			var midX:number = Math.floor(xCoord + halfWidth);
			var el = SVG.createLine( midX, topY, midX, bottomY, color, lineWidth);
		    //$(el).css('stroke-linecap', 'round');

			if (svgElement)
		    	svgElement.appendChild(el);

		    return el;
		}


		static createLine(x1:number, y1:number, x2:number, y2:number, color?:Color, width?:number):SVGElement {
    		var el = <SVGElement>document.createElementNS(SVG._namespace, 'line');
			
			el.setAttribute('x1', x1.toString());
			el.setAttribute('y1', y1.toString());
			el.setAttribute('x2', x2.toString());
			el.setAttribute('y2', y2.toString());

			if (color)
				$(el).css('stroke', color.toString());

			if (width)
				$(el).css('stroke-width', width.toString());

		    return el;
		}


		static createRect(x:number, y:number, width:number, height:number, fillColor:Color, strokeWidth?:number, strokeColor?:Color, opacity?:number):SVGElement {

			// Default values.
			strokeWidth = (typeof(strokeWidth) !== 'undefined' ? strokeWidth : 0);

			if (!strokeColor)
				strokeColor = Color.black;

			opacity = (typeof(opacity) !== 'undefined' ? opacity : 1);

    		var el = <SVGElement>document.createElementNS(SVG._namespace, 'rect');

    		// Make sure width and height are positive.
    		if (height < 0) {
    			y += height;
    			height = -height;
    		}

    		if (width < 0) {
    			x += height;
    			width = -width;
    		}

    		el.setAttribute('x', x.toString());
    		el.setAttribute('y', y.toString());
    		el.setAttribute('width', width.toString());
    		el.setAttribute('height', height.toString());

    		if (typeof(strokeWidth) !== 'undefined')
    			$(el).css('stroke-width', strokeWidth);

    		if (typeof(strokeColor) !== 'undefined')
    			$(el).css('stroke', strokeColor.toString());

    		if (typeof(opacity) !== 'undefined')
    			$(el).css('opacity', opacity);

    		if (typeof(fillColor) !== 'undefined')
    			$(el).css('fill', fillColor.toString());

    		return el;

		}


		static createText(x:number, y:number, text:string, fontName?:string, fontSize?:number, centeredOnX?:boolean, color?:Color):SVGElement {
    		var el = <SVGElement>document.createElementNS(SVG._namespace, 'text');

    		el.setAttribute('x', x.toString());
    		el.setAttribute('y', y.toString());

    		if (fontName)
    			el.setAttribute('font-family', fontName);
    		else
    			el.setAttribute('font-family', "Verdana");

    		if (fontSize)
    			el.setAttribute('font-size', fontSize.toString());
    		else
    			el.setAttribute('font-size', "12");

    		el.textContent = text;

    		// Center on X??
    		if (centeredOnX)
    			el.setAttribute('text-anchor', 'middle');
    		else
    			el.setAttribute('text-anchor', 'start');

    		if (color) {
    			$(el).css('fill', color.toString());
    		}

    		return el;
		}


		// Modify a rect element to round its corners.
		static makeRectRounded(rect, rx, ry) {
    		rect.setAttribute('rx', rx);
    		rect.setAttribute('ry', ry);
		}

		private static _namespace:string = "http://www.w3.org/2000/svg";

	}

} // end module Utl

