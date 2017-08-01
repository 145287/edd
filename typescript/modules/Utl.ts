/// <reference path="../src/EDDDataInterface.ts" />
// This file contains various utility classes under the Utl module.

import * as jQuery from "jquery"
// This file contains various utility classes under the Utl module.
declare function require(name: string): any;
//load dropzone module
var Dropzone = require('dropzone');

export module Utl {

    export class EDD {

        static resolveMeasurementRecordToName(measurementRecord:AssayMeasurementRecord):string {

            var mName = '';
            // We figure out the name and units differently based on the subtype.
            var mst = measurementRecord.mst;
            if (mst == 1) { // Metabolite type.  Magic numbers.  EW!  TODO: Eeeew!
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
            } else if (mst == 2) {  // Gene type.  EWW EWW
                mName = EDDData.GeneTypes[measurementRecord.mt].name;
            } else if (mst == 3) {  // Protein type.  EWW EWW
                mName = EDDData.ProteinTypes[measurementRecord.mt].name;
            }
            return mName;
        }


        static resolveMeasurementRecordToUnits(measurementRecord:AssayMeasurementRecord):string {

            var mUnits = '';
            var mst = measurementRecord.mst;
            if (mst == 1) {     // TODO: https://www.youtube.com/watch?v=JltEXpbGM8s
                if (measurementRecord.uid) {
                    var uRecord = EDDData.UnitTypes[measurementRecord.uid];
                    if (uRecord) {
                        mUnits = uRecord.name;
                    }
                }
            } else if (mst == 2) {
                mUnits = '';    // Units for Proteomics?  Anyone?
            } else if (mst == 3) {
                mUnits = 'RPKM';
            }
            return mUnits;
        }


        static findCSRFToken(): string {
            if (jQuery.cookie) {
                return jQuery.cookie('csrftoken');
            }
            return <string>jQuery('input[name=csrfmiddlewaretoken]').val() || '';
        }


        // Helper function to do a little more prep on objects when calling jQuery's Alax handler.
        // If options contains "data", it is assumed to be a constructed formData object.
        // If options contains a "rawdata" object, it is assumed to be a standard key-value collection
        // If options contains "type", the form type will be set to it - valid values are 'GET' or 'POST'.
        //   If "type" is not specified, it will be 'POST'.
        // If options contains a "progressBar" object, that object is assumed to be an HTML element of type "progress",
        //   and the bar will be updated to reflect the upload and/or download completion.
        static callAjax(options) {
            var debug = options.debug || false;
            var processData = false;
            var formData = options.rawdata || options.data;
            var url = options.url || '';
            var type = options.type || 'POST';
            if ((options.rawdata) && (type != 'POST')) {
                // Turns object name/attribute pairs into a query string, e.g. ?a=4&b=3 .
                // Never what we want when using POST.
                processData = true;
            }
            if (debug) { console.log('Calling ' + url); }
            var headers = {};
            if (type == 'POST') {
                headers["X-CSRFToken"] = EDD.findCSRFToken();
            }
            $.ajax({
                xhr: function() {
                    var xhr = new XMLHttpRequest();
                    if (options.progressBar && (options.upEnd - options.upStart > 0)) {
                        // Specifying evt:any to deal with TypeScript compile error
                        // ">> ../site/ALWindow.ts(197,15): error TS2339: Property 'lengthComputable' does not exist on type 'Event'."
                        xhr.upload.addEventListener("progress", function(evt:any) {
                            if (evt.lengthComputable) {
                                var p = ((evt.loaded / evt.total) * (options.upEnd - options.upStart)) + options.upStart;
                                options.progressBar.setProgress(p);
                                if (debug) { console.log('Upload Progress ' + p + '...'); }
                            } else if (debug) {
                                console.log('Upload Progress...');
                            }
                        }, false);
                    }
                    if (options.progressBar && (options.downEnd - options.downStart > 0)) {
                        xhr.addEventListener("progress", function(evt) {
                            if (evt.lengthComputable) {
                                var p = ((evt.loaded / evt.total) * (options.downEnd - options.downStart)) + options.downStart;
                                options.progressBar.setProgress(p);
                                if (debug) { console.log('Download Progress ' + p + '...'); }
                            } else if (debug) {
                                console.log('Download Progress...');
                            }
                        }, false);
                    }
                    return xhr;
                },
                headers: headers,
                type: type,
                url: url,
                data: formData,
                cache: false,
                error: function( jqXHR, textStatus, errorThrown ) {
                    if (debug) {
                        console.log(textStatus + ' ' + errorThrown);
                        console.log(jqXHR.responseText);
                    }
                },
                contentType: false,
                processData: processData,
                success: function() {
                    var a = Array.prototype.slice.call(arguments, -1);
                    if (debug) { console.log(a[0].responseJSON); }
                    if (options.success) {
                        options.success.apply(this, arguments);
                    }
                }
            });
        }
    }



    export class Tabs {
        // Set up click-to-browse tabs
        static prepareTabs() {
            // declare the click handler at the document level, then filter to any link inside a .tab
            $(document).on('click', '.tabBar span:not(.active)', (e) => {
                var targetTab = $(e.target).closest('span');
                var activeTabs = targetTab.closest('div.tabBar').children('span.active');

                activeTabs.removeClass('active');
                targetTab.addClass('active');

                var targetTabContentID = targetTab.attr('for');
                var activeTabEls = activeTabs.get();

                if (targetTabContentID) {
                    activeTabs.each((i, tab) => {
                        var contentId = $(tab).attr('for');
                        if (contentId) {
                            $(document.getElementById(contentId)).addClass('off');
                        }
                    });
                    $(document.getElementById(targetTabContentID)).removeClass('off');
        }
    }


    // This is currently implemented almost exactly like Tabs above.
    export class ButtonBar {
        // Set up click-to-browse tabs
        static prepareButtonBars() {
            // declare the click handler at the document level, then filter to any link inside a .tab
            $(document).on('click', '.buttonBar span:not(.active)', (e) => {
                var targetButton = $(e.target).closest('span');
                var activeButtons = targetButton.closest('div.buttonBar').children('span.active');

                activeButtons.removeClass('active');
                targetButton.addClass('active');

                var targetButtonContentID = targetButton.attr('for');
                var activeButtonEls = activeButtons.get();

                if (targetButtonContentID) {
                    // Hide the content section for whatever buttons were active, then show the one selected
                    activeButtons.each((i, button) => {
                        var contentId = $(button).attr('for');
                        if (contentId) {
                            $(document.getElementById(contentId)).addClass('off');
                        }
                }
            });
        }
    }


    export class QtipHelper {

            params.position.target = $(linkElement);

            this._contentFunction = contentFunction;

            if (!params.content)
                params.content = {};

            params.content.text = this._generateContent.bind(this);
            this.qtip = $(linkElement).qtip(params);
        }

            // It's incredibly stupid that we have to do this to work around qtip2's 280px
            // max-width default. We have to do it here rather than immediately after calling
            // qtip() because qtip waits to create the actual element.
            $(this._getQTipElement()).css('max-width', 'none').css('width', 'auto');
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

            // If it's something else (like a string) already, just return that value.
            if (typeof clr == 'string')
                return clr;

        }

        }


    };


    export class Table {

            this.table = document.createElement('table');
            this.table.id = tableID;

            if (width)
                $(this.table).css('width', width);

            if (height)
                $(this.table).css('height', height);
        }

            this._currentRow++;
            return this.table.insertRow(-1);
        }

        addColumn(): HTMLElement {
            return this.table.rows.item(this._currentRow - 1).insertCell(-1);
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

            var div;
            if (namespace)
                div = document.createElementNS(namespace, 'div');
            else
                div = document.createElement('div');

            div.innerHTML = str;
            return div.firstChild;

        }


            if (!condition) {
                message = message || "Assertion failed";
                if (typeof Error !== 'undefined') throw Error(message);
                else throw message;
            }
        }


        }


        // Returns a string of length numChars, padding the right side
        // with spaces if str is shorter than numChars.
        // Will truncate if the string is longer than numChars.
                str += ' ';

            return str.slice(0, numChars);
        }


        // Returns a string of length numChars, padding the left side
        // with spaces if str is shorter than numChars.
            var padStr = "";
                padStr += " ";

            return (padStr + str).slice(-numChars);
        }


        // Make a string by repeating the specified string N times.
                ret += str;

            return ret;
        }


        // Convert a size provided in bytes to a nicely formatted string

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
            // We do not want to display ANY decimal point if the value is an integer.
            if (v % 1 === 0) {  // Basic integer test
                return (v % 1).toString();
            }
            if (places > 0) {
                return v.toFixed(places);
            } else if (places == 0) {
                return (v % 1).toString();
            }
            return v.toString();
        }


        static guessFileType(n: string, t: string): string {
            // Going in order from most confident to least confident guesses:
            if (t.indexOf('officedocument.spreadsheet') >= 0) { return 'xlsx'; }
            if (t === 'text/csv') { return 'csv'; }
            if (t === 'text/xml') { return 'xml'; }
            if (n.indexOf('.xml', n.length - 4) !== -1) { return 'xml'; }
            if (t === 'text/plain') { return 'txt'; }
            if (n.indexOf('.txt', n.length - 4) !== -1) { return 'txt'; }
            return 'csv';
        }


        // Given a date in seconds (with a possible fractional portion being milliseconds),
        // based on zero being midnight of Jan 1, 1970 (standard old-school POSIX time),
        // return a string formatted in the manner of "Dec 21 2012, 11:45am",
        // with exceptions for 'Today' and 'Yesterday', e.g. "Yesterday, 3:12pm".

            if (!timestamp || timestamp < 1) {
                return '<span style="color:#888;">N/A</span>';
            }

                day_str = 'Today';
                day_str = 'Yesterday';
            } else {
            }

        }


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


    // {
    //  elementId: ID of the element to be set up as a drop zone
    // }

    export class FileDropZone {

        csrftoken: any;
        fileInitFn: any;


            this.csrftoken = EDD.findCSRFToken();
            this.fileInitFn = options.fileInitFn;


        // Helper function to create and set up a FileDropZone.
        static create(options:any): void {
            var h = new FileDropZone(options);
        }


            });
                    // If we were given a function to process the error, use it.
                }
                    } else {
                    }
                }
                }
                }
                }
            });
    }


    // SVG-related utilities.
    export class SVG {

            svgElement.setAttribute('version', '1.2');
            svgElement.setAttribute('width', width.toString());
            svgElement.setAttribute('height', height.toString());
            svgElement.setAttribute('viewBox', '0 0 ' + boxWidth + ' ' + boxHeight);
            svgElement.setAttribute('preserveAspectRatio', 'none');
            return svgElement;
        }


        // Creates a vertical line centered on (xCoord,yCoord).


            if (svgElement)
                svgElement.appendChild(el);

            return el;
        }


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
