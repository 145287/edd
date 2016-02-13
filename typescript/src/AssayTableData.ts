/// <reference path="typescript-declarations.d.ts" />
/// <reference path="Utl.ts" />


declare var ATData: any; // Setup by the server.
declare var EDDATDGraphing: any;
declare var EDD_auto: any;


// Type name for the grid of values pasted in
interface RawInput extends Array<string[]> { }
// type for the stats generated from parsing input text
interface RawInputStat {
    input: RawInput;
    columns: number;
}


// This module encapsulates all the custom code for the data import page.
// It consists primarily of a series of classes, each corresponding to a step in the import process,
// with a corresponding chunk of UI on the import page.
// Each class pulls data from one or more previous steps, does some internal processing,
// then triggers a callback function, announcing the availability of its own new data.
// The callback function triggers the instance of the next step.
module EDDTableImport {
    'use strict';

    // During initialization we will allocate one instance of each of the classes
    // that handle the major steps of the import process.
    // These are specified in the order they are called, and the order they appear on the page:
    export var selectMajorKindStep: SelectMajorKindStep;
    export var rawInputStep: RawInputStep;
    export var identifyStructuresStep: IdentifyStructuresStep;
    export var typeDisambiguationStep: TypeDisambiguationStep;


    interface MeasurementValueSequence {
        data:string[][];
    }

    interface GraphingSet extends MeasurementValueSequence {
        label: string;
        name: string;
        units: string;
        color?: string;
        tags?: any;
    }
    // These are returned by the server after parsing a dropped file
    interface RawImportSet extends MeasurementValueSequence {
        kind: string;
        line_name: string;
        assay_name: string;
        measurement_name: string;
        metadata_by_name?: {[id:string]: string},
    }
    // This information is added post-disambiguation, in addition to the fields from RawImportSet, and sent to the server
    interface ResolvedImportSet extends RawImportSet {
        protocol_id:string;
        line_id:string;    // Value of 'null' or string 'new' indicates new Line should be created with name line_name. 
        assay_id:string;
        measurement_id:string;
        compartment_id:string;
        units_id:string;
        metadata_by_id:{[id:string]: string};
    }


    // As soon as the window load signal is sent, call back to the server for the set of reference records
    // that will be used to disambiguate labels in imported data.
    export function onWindowLoad(): void {
        var atdata_url = "/study/" + EDDData.currentStudyID + "/assaydata";

        $('.disclose').find('a.discloseLink').on('click', EDDTableImport.disclose);

        // Populate ATData and EDDData objects via AJAX calls
        jQuery.ajax(atdata_url, {
            "success": function(data) {
                ATData = data.ATData;
                $.extend(EDDData, data.EDDData);
                EDDTableImport.onReferenceRecordsLoad();
            }
        }).fail(function(x, s, e) {
            alert(s);
        });
    }


    // As soon as we've got and parsed the reference data, we can set up all the callbacks for the UI,
    // effectively turning the page "on".
    export function onReferenceRecordsLoad(): void {

        // Allocate one instance of each step, providing references to the previous steps as needed.
        var a = new SelectMajorKindStep(EDDTableImport.selectMajorKindCallback);
        var b = new RawInputStep(a, EDDTableImport.rawInputCallback);
        var c = new IdentifyStructuresStep(a, b, EDDTableImport.identifyStructuresCallback);
        var d = new TypeDisambiguationStep(a, c, EDDTableImport.typeDisambiguationCallback);

        EDDTableImport.selectMajorKindStep = a;
        EDDTableImport.rawInputStep = b;
        EDDTableImport.identifyStructuresStep = c;
        EDDTableImport.typeDisambiguationStep = d;

        // Wire up the function that submits the page
        $('#submitForImport').on('click', EDDTableImport.submitForImport);

        // We need to manually trigger this, after all our steps are constructed.
        // This will cascade calls through the rest of the steps and configure them too.
        a.reconfigure();
    }


    // This is called by our instance of selectMajorKindStep to announce changes.
    export function selectMajorKindCallback(): void {
        // This is a bit of a hack.  We want to change the pulldown settings in Step 3 if the mode in Step 1 is changed,
        // but leave the pulldown alone otherwise (including when Step 2 announces its own changes.)
        // TODO: Make Step 3 track this with an internal variable.
        if (EDDTableImport.selectMajorKindStep.interpretationMode == 'mdv') {
            // A default set of pulldown settings for this mode
            EDDTableImport.identifyStructuresStep.pulldownSettings = [TypeEnum.Assay_Line_Names, TypeEnum.Metabolite_Name];
        }
        EDDTableImport.rawInputStep.previousStepChanged();
    }


    // This is called by our instance of Step 2, RawInputStep to announce changes.
    // We just pass the signal along to Step 3: IdentifyStructuresStep.
    export function rawInputCallback(): void {
        EDDTableImport.identifyStructuresStep.previousStepChanged();
    }


    // This is called by our instance of Step 3, IdentifyStructuresStep to announce changes.
    // We just pass the signal along to Step 4: TypeDisambiguationStep.
    export function identifyStructuresCallback(): void {
        EDDTableImport.typeDisambiguationStep.previousStepChanged();
    }


    // This is called by our instance of TypeDisambiguationStep to announce changes.
    // All we do currently is repopulate the debug area.
    export function typeDisambiguationCallback(): void {
//        var parsedSets = EDDTableImport.identifyStructuresStep.parsedSets;
        var resolvedSets = EDDTableImport.typeDisambiguationStep.createSetsForSubmission();
        // if the debug area is there, set its value to JSON of parsed sets
        $('#jsondebugarea').val(JSON.stringify(resolvedSets));
    }


    // When the submit button is pushed, fetch the most recent record sets from our IdentifyStructuresStep instance,
    // and embed them in the hidden form field that will be submitted to the server.
    // Note that this is not all that the server needs, in order to successfully process an import.
    // It also reads other form elements from the page, created by SelectMajorKindStep and TypeDisambiguationStep.
    export function submitForImport(): void {
        var json: string;
        var resolvedSets = EDDTableImport.typeDisambiguationStep.createSetsForSubmission();
        json = JSON.stringify(resolvedSets);
        $('#jsonoutput').val(json);
        $('#jsondebugarea').val(json);
    }


    // The usual click-to-disclose callback.  Perhaps this should be in Utl.ts?
    export function disclose(): boolean {
        $(this).closest('.disclose').toggleClass('discloseHide');
        return false;
    }


    // The class responsible for everything in the "Step 1" box that you see on the data import page.
    // Here we provide UI for selecting the major kind of import, and the Protocol that the data should be stored under.
    // These choices affect the behavior of all subsequent steps.
    export class SelectMajorKindStep {

        // The Protocol for which we will be importing data.
        masterProtocol: number;
        // The main mode we are interpreting data in.
        // Valid values sofar are "std", "mdv", "tr", "pr", and "biolector".
        interpretationMode: string;
        inputRefreshTimerID: number;

        nextStepCallback: any;


        constructor(nextStepCallback: any) {
            this.masterProtocol = 0;
            this.interpretationMode = null;    // We rely on a separate call to reconfigure() to set this properly.
            this.inputRefreshTimerID = null;

            this.nextStepCallback = nextStepCallback;

            var reProcessOnChange: string[];

            reProcessOnChange = ['#stdlayout', '#trlayout', '#prlayout', '#mdvlayout', '#biolectorlayout'];

            // This is rather a lot of callbacks, but we need to make sure we're
            // tracking the minimum number of elements with this call, since the
            // function called has such strong effects on the rest of the page.
            // For example, a user should be free to change "merge" to "replace" without having
            // their edits in Step 2 erased.
            $("#masterProtocol").change(this.reconfigure.bind(this));

            // Using "change" for these because it's more efficient AND because it works around an
            // irritating Chrome inconsistency
            // For some of these, changing them shouldn't actually affect processing until we implement
            // an overwrite-checking feature or something similar
            $(reProcessOnChange.join(',')).on('click', this.queueReconfigure.bind(this));
        }


        // Start a timer to wait before calling the reconfigure routine.
        // This way we condense multiple possible events from the radio buttons and/or pulldown into one.
        queueReconfigure(): void {
            if (this.inputRefreshTimerID) {
                clearTimeout(this.inputRefreshTimerID);
            }
            this.inputRefreshTimerID = setTimeout(this.reconfigure.bind(this), 5);
        }


        // Read the settings out of the UI and pass along.
        // If the interpretation mode has changed, all the subsequent steps will need a refresh.
        // If the master Protocol pulldown has changed, Step 4 will need a refresh,
        // specifically the master Assay pulldown and Assay/Line disambiguation section.
        reconfigure(): void {
            // Don't inline these into the if statement or the second one might not be called!
            var a:boolean = this.checkInterpretationMode();
            var b:boolean = this.checkMasterProtocol();
            if (a || b) { this.nextStepCallback(); }
        }


        // If the interpretation mode value has changed, note the change and return 'true'.
        // Otherwise return 'false'.
        checkInterpretationMode(): boolean {
            // Find every input element of type 'radio' with the name attribute of 'datalayout' that's checked.
            // Should return 0 or 1 elements.
            var modeRadio = $("input[type='radio'][name='datalayout']:checked");
            // If none of them are checked, we don't have enough information to handle any next steps.
            if (modeRadio.length < 1) { return false; }
            var radioValue = modeRadio.val();
            if (this.interpretationMode == radioValue) { return false; }
            this.interpretationMode = radioValue;
            return true;
        }


        // If the master Protocol pulldown value has changed, note the change and return 'true'.
        // Otherwise return 'false'.
        checkMasterProtocol():boolean {
            var protocolIn = $('#masterProtocol');
            var p = parseInt(protocolIn.val(), 10);
            if (this.masterProtocol === p) { return false; }
            this.masterProtocol = p;
            return true;
        }
    }



    // The class responsible for everything in the "Step 2" box that you see on the data import page.
    // It needs to parse the raw data from typing or pasting in the input box, or a dragged-in file,
    // into a null-padded rectangular grid that can be easily used by the next step.
    // Depending on the kind of import chosen in Step 1, this step will accept different kinds of files,
    // and handle the file drag in different ways.
    // For example, when the import kind is "Standard" and the user drags in a CSV file, the file is parsed
    // in-browser and the contents are placed in the text box.  When the import kind is "biolector" and the user
    // drags in an XML file, the file is sent to the server and parsed there, and the resulting data is passed
    // back to the browser and placed in the text box.
    export class RawInputStep {

        // This is where we organize raw data pasted into the text box by the user,
        // or placed there as a result of server-side processing - like taking apart a dropped Excel file.

        private gridFromTextField: any[];
        gridRowMarkers: any[];

        // This is where we handle dropped files, and the semi-processed record sets that the server returns,
        // from interpreting an XML Biolector file for example.

        activeDraggedFile: any;
        processedSetsFromFile: any[];
        processedSetsAvailable: boolean;
        fileUploadProgressBar: Utl.ProgressBar;

        // Additional options for interpreting text box data, exposed in the UI for the user to tweak.
        // Sometimes set automatically by certain import modes, like the "mdv" mode.

        transpose: boolean;
        // If the user deliberately chose to transpose or not transpose, disable the attempt
        // to auto-determine transposition.
        userClickedOnTranspose: boolean;
        // Whether to interpret the pasted data row-wise or column-wise, when importing
        // either measurements or metadata.
        ignoreDataGaps: boolean;
        userClickedOnIgnoreDataGaps: boolean;
        separatorType: string;

        inputRefreshTimerID: any;

        selectMajorKindStep: SelectMajorKindStep;
        nextStepCallback: any;


        constructor(selectMajorKindStep: SelectMajorKindStep, nextStepCallback: any) {

            this.selectMajorKindStep = selectMajorKindStep;

            this.gridFromTextField = [];
            this.processedSetsFromFile = [];
            this.processedSetsAvailable = false;
            this.gridRowMarkers = [];
            this.transpose = false;
            this.userClickedOnTranspose = false;
            this.ignoreDataGaps = false;
            this.userClickedOnIgnoreDataGaps = false;
            this.separatorType = 'csv';
            this.inputRefreshTimerID = null;

            $('#step2textarea')
                .on('paste', this.pastedRawData.bind(this))
                .on('keyup', this.queueReprocessRawData.bind(this))
                .on('keydown', this.suppressNormalTab.bind(this));

            // Using "change" for these because it's more efficient AND because it works around an
            // irritating Chrome inconsistency
            // For some of these, changing them shouldn't actually affect processing until we implement
            // an overwrite-checking feature or something similar

            $('#rawdataformatp').on('change', this.queueReprocessRawData.bind(this));
            $('#ignoreGaps').on('change', this.clickedOnIgnoreDataGaps.bind(this));
            $('#transpose').on('change', this.clickedOnTranspose.bind(this));
            $('#resetstep2').on('click', this.reset.bind(this));

            this.fileUploadProgressBar = new Utl.ProgressBar('fileUploadProgressBar');

            Utl.FileDropZone.create({
                elementId: "step2textarea",
                fileInitFn: this.fileDropped.bind(this),
                processRawFn: this.fileRead.bind(this),
                url: "/utilities/parsefile",
                processResponseFn: this.fileReturnedFromServer.bind(this),
                progressBar: this.fileUploadProgressBar
            });
            this.clearDropZone();
            this.queueReprocessRawData();

            this.nextStepCallback = nextStepCallback;
        }


        // In practice, the only time this will be called is when Step 1 changes,
        // which may call for a reconfiguration of the controls in this step.
        previousStepChanged(): void {
            var mode = this.selectMajorKindStep.interpretationMode;

            // By default, our drop zone wants excel or csv files, so we clear additional class:
            $('#step2textarea').removeClass('xml');

            if (mode === 'biolector') {
                // Biolector data is expected in XML format.
                $('#step2textarea').addClass('xml');
                // It is also expected to be dropped from a file.
                // So either we're already in file mode and there are already parsed sets available,
                // Or we are in text entry mode waiting for a file drop.
                // Either way there's no need to call reprocessRawData(), so we just push on to the next step.
                this.nextStepCallback();
                return;
            }
            if (mode === 'mdv') {
                // When JBEI MDV format documents are pasted in, it's always from Excel, so they're always tab-separated.
                this.setSeparatorType('tab');
                // We also never ignore gaps, or transpose, for MDV documents.
                this.setIgnoreGaps(false);
                this.setTranspose(false);
                // Proceed through to the dropzone check.
            }
            if (mode === 'std' || mode === 'tr' || mode === 'pr' || mode === 'mdv') {
                // If an excel file was dropped in, its content was pulled out and dropped into the text box.
                // The only reason we would want to still show the file info area is if we are currently in the middle
                // of processing a file and haven't yet received its worksheets from the server.
                // We can determine that by checking the status of any existing FileDropZoneFileContainer.
                // If it's stale, we clear it so the user can drop in another file.
                if (this.activeDraggedFile) {
                    if (this.activeDraggedFile.allWorkFinished) {
                        this.clearDropZone();
                    }
                }
                this.queueReprocessRawData();
            }
        }


        queueReprocessRawData(): void {
            // Start a timer to wait before calling the routine that remakes the graph.
            // This way we're not bothering the user with the long redraw process when
            // they are making fast edits.
            if (this.inputRefreshTimerID) {
                clearTimeout(this.inputRefreshTimerID);
            }
            this.inputRefreshTimerID = setTimeout(this.reprocessRawData.bind(this), 350);
        }


        reprocessRawData(): void {

            var mode: string, delimiter: string, input: RawInputStat;

            mode = this.selectMajorKindStep.interpretationMode;

            this.setIgnoreGaps();
            this.setTranspose();
            this.setSeparatorType();

            this.gridFromTextField = [];
            this.gridRowMarkers = [];

            delimiter = '\t';
            if (this.separatorType === 'csv') {
                delimiter = ',';
            }
            input = this.parseRawInput(delimiter, mode);

            // We meed at least 2 rows and columns for MDV format to make any sense

            if (mode === "mdv") {
                // MDV format is quite different, so we parse it in its own subroutine.
                if ((input.input.length > 1) && (input.columns > 1)) {
                    this.processMdv(input.input);
                }
            } else {
                // All other formats (so far) are interpreted from a grid.
                // Even biolector XML - which is converted to a grid on the server, then passed back.

                // Note that biolector is left out here - we don't want to do any "inferring" with that data.
                if (mode === 'std' || mode === 'tr' || mode === 'pr') {
                    // If the user hasn't deliberately chosen a setting for 'transpose', we will do
                    // some analysis to attempt to guess which orientation the data needs to have.
                    if (!this.userClickedOnTranspose) {
                        this.inferTransposeSetting(input.input);
                    }
                    // If the user hasn't deliberately chosen to ignore, or accept, gaps in the data,
                    // do a basic analysis to guess which setting makes more sense.
                    if (!this.userClickedOnIgnoreDataGaps) {
                        this.inferGapsSetting();
                    }
                }

                // Collect the data based on the settings
                if (this.transpose) {
                    // first row becomes Y-markers as-is
                    this.gridRowMarkers = input.input.shift() || [];
                    this.gridFromTextField = (input.input[0] || []).map((_, i: number): string[] => {
                        return input.input.map((row: string[]): string => row[i] || '');
                    });
                } else {
                    this.gridRowMarkers = [];
                    this.gridFromTextField = (input.input || []).map((row: string[]): string[] => {
                        this.gridRowMarkers.push(row.shift());
                        return row;
                    });
                }

                // Give labels to any header positions that got 'null' for a value.
                this.gridRowMarkers = this.gridRowMarkers.map((value: string) => value || '?');
            }

            this.nextStepCallback();
        }


        // Here, we take a look at the type of the dropped file and decide whether to
        // send it to the server, or process it locally.
        // We inform the FileDropZone of our decision by setting flags in the fileContiner object,
        // which will be inspected when this function returns.
        fileDropped(fileContainer): void {
            var mode = this.selectMajorKindStep.interpretationMode;
            // We'll process csv files locally.
            if ((fileContainer.fileType === 'csv') &&
                    (mode === 'std' || mode === 'tr' || mode === 'pr')) {
                fileContainer.skipProcessRaw = false;
                fileContainer.skipUpload = true;
                return;
            }
            // With Excel documents, we need some server-side tools.
            // We'll signal the dropzone to upload this, and receive processed results.
            if ((fileContainer.fileType === 'excel') &&
                    (mode === 'std' || mode === 'tr' || mode === 'pr' || mode === 'mdv')) {
                this.showDropZone(fileContainer);
                fileContainer.skipProcessRaw = true;
                fileContainer.skipUpload = false;
                return;
            }
            if (fileContainer.fileType === 'xml' && mode === 'biolector') {
                this.showDropZone(fileContainer);
                fileContainer.skipProcessRaw = true;
                fileContainer.skipUpload = false;
                return;
            }
            // By default, skip any further processing
            fileContainer.skipProcessRaw = true;
            fileContainer.skipUpload = true;
        }


        // This function is passed the usual fileContainer object, but also a reference to the
        // full content of the dropped file.  So, for example, in the case of parsing a csv file,
        // we just drop that content into the text box and we're done.
        fileRead(fileContainer, result): void {
            if (fileContainer.fileType === 'csv') {
                // Since we're handling this format entirely client-side, we can get rid of the
                // drop zone immediately.
                fileContainer.skipUpload = true;
                this.clearDropZone();
                $("#step2textarea").val(result);
                this.inferSeparatorType();
                return;
            }
        }


        // This is called upon receiving a response from a file upload operation,
        // and unlike fileRead() above, is passed a processed result from the server as a second argument,
        // rather than the raw contents of the file.
        fileReturnedFromServer(fileContainer, result): void {
            // Whether we clear the file info area entirely, or just update its status,
            // we know we no longer need the 'sending' status.
            $('#fileDropInfoSending').addClass('off');
            if (fileContainer.fileType == "excel") {
                this.clearDropZone();
                var ws = result.file_data["worksheets"][0];
                var table = ws[0];
                var csv = [];
                if (table.headers) {
                    csv.push(table.headers.join());
                }
                for (var i = 0; i < table.values.length; i++) {
                    csv.push(table.values[i].join());
                }
                this.setSeparatorType('csv');
                $("#step2textarea").val(csv.join("\n"));
                this.reprocessRawData();
                return;
            }
            if (fileContainer.fileType == "xml") {
                var d = result.file_data;
                var t = 0;
                d.forEach((set:any): void => { t += set.data.length; });
                $('<p>').text('Found ' + d.length + ' measurements with ' + t + ' total data points.').appendTo($("#fileDropInfoLog"));
                this.processedSetsFromFile = d;
                this.processedSetsAvailable = true;
                // Call this directly, skipping over reprocessRawData() since we don't need it.
                this.nextStepCallback();
                return;
            }
        }


        parseRawInput(delimiter: string, mode: string):RawInputStat {
            var rawText: string, longestRow: number, rows: RawInput, multiColumn: boolean;
            rawText = $('#step2textarea').val();
            rows = [];
            // find the highest number of columns in a row
            longestRow = rawText.split(/[ \r]*\n/).reduce((prev: number, rawRow: string): number => {
                var row: string[];
                if (rawRow !== '') {
                    row = rawRow.split(delimiter);
                    rows.push(row);
                    return Math.max(prev, row.length);
                }
                return prev;
            }, 0);
            // pad out rows so it is rectangular
            if (mode === 'std' || mode === 'tr' || mode === 'pr') {
                rows.forEach((row: string[]): void => {
                    while (row.length < longestRow) {
                        row.push('');
                    }
                });
            }
            return {
                'input': rows,
                'columns': longestRow
            };
        }


        // Reset and hide the info box that appears when a file is dropped,
        // and reveal the text entry area.
        // This also clears the "processedSetsAvailable" flag because it assumes that
        // the text entry area is now the preferred data source for subsequent steps.

        clearDropZone(): void {
            $('#step2textarea').removeClass('off');
            $('#fileDropInfoArea').addClass('off');
            $('#fileDropInfoSending').addClass('off');
            $('#fileDropInfoName').empty();
            $('#fileDropInfoLog').empty();
            // If we have a currently tracked dropped file, set its flags so we ignore any callbacks,
            // before we forget about it.
            if (this.activeDraggedFile) {
                this.activeDraggedFile.stopProcessing = true;
            }
            this.activeDraggedFile = null;
            this.processedSetsAvailable = false;
        }


        // Reset and hide the info box that appears when a file is dropped,
        // and reveal the text entry area.
        showDropZone(fileContainer): void {
            // Set the icon image properly
            $('#fileDropInfoIcon').removeClass('xml');
            $('#fileDropInfoIcon').removeClass('excel');
            if (fileContainer.fileType === 'xml') {
                $('#fileDropInfoIcon').addClass('xml');
            } else if (fileContainer.fileType === 'excel') {
                $('#fileDropInfoIcon').addClass('excel');
            }
            $('#step2textarea').addClass('off');
            $('#fileDropInfoArea').removeClass('off');
            $('#fileDropInfoSending').removeClass('off');
            $('#fileDropInfoName').text(fileContainer.file.name)
            $('#fileUploadMessage').text('Sending ' + Utl.JS.sizeToString(fileContainer.file.size) + ' To Server...');
//            $('#fileDropInfoLog').empty();
            this.activeDraggedFile = fileContainer;
        }


        reset(): void {
            this.clearDropZone();
            $('#step2textarea').val('');
            this.reprocessRawData();
        }


        inferTransposeSetting(rows: RawInput):void  {
            // The most straightforward method is to take the top row, and the first column,
            // and analyze both to see which one most likely contains a run of timestamps.
            // We'll also do the same for the second row and the second column, in case the
            // timestamps are underneath some other header.
            var arraysToAnalyze: string[][], arraysScores: number[], setTranspose: boolean;
        
            // Note that with empty or too-small source data, these arrays will either remain
            // empty, or become 'null'
            arraysToAnalyze = [
                rows[0] || [],   // First row
                rows[1] || [],   // Second row
                (rows || []).map((row: string[]): string => row[0]),   // First column
                (rows || []).map((row: string[]): string => row[1])    // Second column
            ];
            arraysScores = arraysToAnalyze.map((row: string[], i: number): number => {
                var score = 0, prev: number, nnPrev: number;
                if (!row || row.length === 0) {
                    return 0;
                }
                prev = nnPrev = undefined;
                row.forEach((value: string, j: number, r: string[]): void => {
                    var t: number;
                    if (value) {
                        t = parseFloat(value.replace(/,/g, ''));
                    }
                    if (!isNaN(t)) {
                        if (!isNaN(prev) && t > prev) {
                            score += 2;
                        } else if (!isNaN(nnPrev) && t > nnPrev) {
                            score += 1;
                        }
                        nnPrev = t;
                    }
                    prev = t;
                });
                return score / row.length;
            });
            // If the first row and column scored differently, judge based on them.
            // Only if they scored the same do we judge based on the second row and second column.
            if (arraysScores[0] !== arraysScores[2]) {
                setTranspose = arraysScores[0] > arraysScores[2];
            } else {
                setTranspose = arraysScores[1] > arraysScores[3];
            }
            this.setTranspose(setTranspose);
        }


        inferGapsSetting():void {
            // Count the number of blank values at the end of each column
            // Count the number of blank values in between non-blank data
            // If more than three times as many as at the end, default to ignore gaps
            var intra: number = 0, extra: number = 0;
            this.gridFromTextField.forEach((row: string[]): void => {
                var notNull: boolean = false;
                // copy and reverse to loop from the end
                row.slice(0).reverse().forEach((value: string): void => {
                    if (!value) {
                        notNull ? ++extra : ++intra;
                    } else {
                        notNull = true;
                    }
                });
            });
            var result:boolean = extra > (intra * 3);
            this.setIgnoreGaps(result);
        }


        processMdv(input: RawInput):void {
            var rows: RawInput, colLabels: string[], compounds: any, orderedComp: string[];
            colLabels = [];
            rows = input.slice(0); // copy
            // If this word fragment is in the first row, drop the whole row.
            // (Ignoring a Q of unknown capitalization)
            if (rows[0].join('').match(/uantitation/g)) {
                rows.shift();
            }
            compounds = {};
            orderedComp = [];
            rows.forEach((row: string[]): void => {
                var first: string, marked: string[], name: string, index: number;
                first = row.shift();
                // If we happen to encounter an occurrence of a row with 'Compound' in
                // the first column, we treat it as a row of column identifiers.
                if (first === 'Compound') {
                    colLabels = row;
                    return;
                }
                marked = first.split(' M = ');
                if (marked.length === 2) {
                    name = marked[0];
                    index = parseInt(marked[1], 10);
                    if (!compounds[name]) {
                        compounds[name] = { 'originalRows': {}, 'processedAssayCols': {} }
                        orderedComp.push(name);
                    }
                    compounds[name].originalRows[index] = row.slice(0);
                }
            });
            $.each(compounds, (name: string, value: any): void => {
                var indices: number[];
                // First gather up all the marker indexes given for this compound
                indices = $.map(value.originalRows, (_, index: string): number => parseInt(index, 10));
                indices.sort((a, b) => a - b); // sort ascending
                // Run through the set of columnLabels above, assembling a marking number for each,
                // by drawing - in order - from this collected row data.
                colLabels.forEach((label: string, index: number): void => {
                    var parts: string[], anyFloat: boolean;
                    parts = [];
                    anyFloat = false;
                    indices.forEach((ri: number): void => {
                        var original: string[], cell: string;
                        original = value.originalRows[ri];
                        cell = original[index];
                        if (cell) {
                            cell = cell.replace(/,/g, '');
                            if (isNaN(parseFloat(cell))) {
                                if (anyFloat) {
                                    parts.push('');
                                }
                            } else {
                                parts.push(cell);
                            }
                        }
                    });
                    // Assembled a full carbon marker number, grab the column label, and place
                    // the marker in the appropriate section.
                    value.processedAssayCols[index] = parts.join('/');
                });
            });
            // Start the set of row markers with a generic label
            this.gridRowMarkers = ['Assay'];
            // The first row is our label collection
            this.gridFromTextField[0] = colLabels.slice(0);
            // push the rest of the rows generated from ordered list of compounds
            Array.prototype.push.apply(
                this.gridFromTextField,
                orderedComp.map((name: string): string[] => {
                    var compound: any, row: string[], colLookup: any;
                    this.gridRowMarkers.push(name);
                    compound = compounds[name];
                    row = [];
                    colLookup = compound.processedAssayCols;
                    // generate row cells by mapping column labels to processed columns
                    Array.prototype.push.apply(row,
                        colLabels.map((_, index: number): string => colLookup[index] || '')
                    );
                    return row;
                })
            );
        }


        // This gets called when there is a paste event.
        pastedRawData():void {
            // We do this using a timeout so the rest of the paste events fire, and get the pasted result.
            window.setTimeout(this.inferSeparatorType.bind(this), 1);
        }


        inferSeparatorType(): void {
            if (this.selectMajorKindStep.interpretationMode !== "mdv") {
                var text: string = $('#step2textarea').val() || '', test: boolean;
                test = text.split('\t').length >= text.split(',').length;
                this.setSeparatorType(test ? 'tab' : 'csv');
            }
        }


        setIgnoreGaps(value?: boolean): void {
            var ignoreGaps = $('#ignoreGaps');
            if (value === undefined) {
                value = ignoreGaps.prop('checked');
            } else {
                ignoreGaps.prop('checked', value);
            }
            this.ignoreDataGaps = value;
        }


        setTranspose(value?: boolean): void {
            var transpose = $('#transpose');
            if (value === undefined) {
                value = transpose.prop('checked');
            } else {
                transpose.prop('checked', value);
            }
            this.transpose = value;
        }


        setSeparatorType(value?: string): void {
            var separatorPulldown = $('#rawdataformatp');
            if (value === undefined) {
                value = separatorPulldown.val();
            } else {
                separatorPulldown.val(value);
            }
            this.separatorType = value;
        }


        clickedOnIgnoreDataGaps():void {
            this.userClickedOnIgnoreDataGaps = true;
            this.reprocessRawData();    // This will take care of reading the status of the checkbox
        }


        clickedOnTranspose():void {
            this.userClickedOnTranspose = true;
            this.reprocessRawData();
        }


        // This handles insertion of a tab into the textarea.
        // May be glitchy.
        suppressNormalTab(e: JQueryKeyEventObject): boolean {
            var input: HTMLInputElement, text: string;
            if (e.which === 9) {
                input = <HTMLInputElement>e.target;
                text = $(input).val();
                // set value to itself with selection replaced by a tab character
                $(input).val([
                    text.substring(0, input.selectionStart),
                    text.substring(input.selectionEnd)
                ].join('\t'));
                // put caret at right position again
                input.selectionStart = input.selectionEnd = input.selectionStart + 1;
                return false;
            }
            return true;
        }


        getGrid(): any[] {
            return this.gridFromTextField;
        }
    }



    // type for the options in row pulldowns
    // TODO update to use unions when migrating to Typescript 1.4+
    interface RowPulldownOption extends Array<any> { // Array<string|number|RowPulldownOption[]>
        0: string;
        1: any; // number | RowPulldownOption[]
    }


    // Magic numbers used in pulldowns to assign types to rows/fields.
    export class TypeEnum {
        static Gene_Names = 10;
        static RPKM_Values = 11;
        static Assay_Line_Names = 1;
        static Protein_Name = 12;
        static Metabolite_Names = 2;
        static Timestamp = 3;
        static Metadata_Name = 4;
        static Metabolite_Name = 5;
    }


    // The class responsible for everything in the "Step 3" box that you see on the data import page.
    // Get the grid from the previous step, and draw it as a table with puldowns for specifying the content
    // of the rows and columns, as well as checkboxes to enable or disable rows or columns.
    // Interpret the current grid and the settings on the current table into EDD-friendly sets.
    export class IdentifyStructuresStep {

        rowLabelCells: any[];
        colCheckboxCells: any[];
        rowCheckboxCells: any[];    // Note: this is built, but never referenced...  Might as well cut it.

        colObjects: any[];
        dataCells: any[];

        // We keep a single flag for each data point [y,x]
        // as well as two linear sets of flags for enabling or disabling
        // entire columns/rows.
        activeColFlags: any[];
        activeRowFlags: any[];
        activeFlags: any[];

        // Arrays for the pulldown menus on the left side of the table.
        // These pulldowns are used to specify the data type - or types - contained in each
        // row of the pasted data.
        pulldownObjects: any[];
        pulldownSettings: any[];
        // We also keep a set of flags to track whether a pulldown was changed by a user and
        // will not be recalculated.
        pulldownUserChangedFlags: any[];

        graphEnabled:boolean;
        graphRefreshTimerID: any;

        // Data structures pulled from the Step 2 grid or server response,
        // and composed into sets suitable for submission to the server.
        parsedSets: RawImportSet[];
        graphSets: GraphingSet[];
        uniqueLineNames: any[];
        uniqueAssayNames: any[];
        uniqueMeasurementNames: any[];
        uniqueMetadataNames: any[];
        // A flag to indicate whether we have seen any timestamps specified in the import data
        seenAnyTimestamps: boolean;

        rawInputStep: RawInputStep;
        selectMajorKindStep: SelectMajorKindStep;
        nextStepCallback: any;


        constructor(selectMajorKindStep: SelectMajorKindStep, rawInputStep: RawInputStep, nextStepCallback: any) {

            this.rawInputStep = rawInputStep;

            this.rowLabelCells = [];
            this.colCheckboxCells = [];
            this.colObjects = [];
            this.dataCells = [];

            // We keep a single flag for each data point [y,x]
            // as well as two linear sets of flags for enabling or disabling
            // entire columns/rows.
            this.activeColFlags = [];
            this.activeRowFlags = [];
            this.activeFlags = [];

            // Arrays for the pulldown menus on the left side of the table.
            // These pulldowns are used to specify the data type - or types - contained in each
            // row of the pasted data.
            this.pulldownObjects = [];
            this.pulldownSettings = [];
            // We also keep a set of flags to track whether a pulldown was changed by a user and
            // will not be recalculated.
            this.pulldownUserChangedFlags = [];

            this.graphEnabled = true;
            this.graphRefreshTimerID = null;

            this.parsedSets = [];
            this.graphSets = [];
            this.uniqueLineNames = [];
            this.uniqueAssayNames = [];
            this.uniqueMeasurementNames = [];
            this.uniqueMetadataNames = [];
            // A flag to indicate whether we have seen any timestamps specified in the import data
            this.seenAnyTimestamps = false;

            this.selectMajorKindStep = selectMajorKindStep;
            this.nextStepCallback = nextStepCallback;

            $('#dataTableDiv')
                .on('mouseover mouseout', 'td', this.highlighterF.bind(this))
                .on('dblclick', 'td', this.singleValueDisablerF.bind(this));

            $('#resetstep3').on('click', this.resetEnabledFlagMarkers.bind(this));
        }


        previousStepChanged(): void {
            
            var mode = this.selectMajorKindStep.interpretationMode;

            var graph = $('#graphDiv');
            if (mode === 'std' || mode === 'biolector') {
                this.graphEnabled = true;
            } else {
                this.graphEnabled = false;
            }
            graph.toggleClass('off', !this.graphEnabled);

            var gridRowMarkers = this.rawInputStep.gridRowMarkers;
            var grid = this.rawInputStep.getGrid();
            var ignoreDataGaps = this.rawInputStep.ignoreDataGaps;

            if (mode === 'std' || mode === 'tr' || mode === 'pr') {
                gridRowMarkers.forEach((value: string, i: number): void => {
                    var type: any;
                    if (!this.pulldownUserChangedFlags[i]) {
                        type = this.figureOutThisRowsDataType(mode, value, grid[i] || []);
                        this.pulldownSettings[i] = type;
                    }
                });
            }

            // We're emptying the data table whether we remake it or not...
            $('#dataTableDiv').empty();

            if (mode === 'std' || mode === 'tr' || mode === 'pr' || mode === 'mdv') {
                // Create a map of enabled/disabled flags for our data,
                // but only fill the areas that do not already exist.
                this.inferActiveFlags(grid);
                // Construct table cell objects for the page, based on our extracted data
                this.constructDataTable(mode, grid, gridRowMarkers);
                // and leaving out any values that have been individually flagged.
                // Update the styles of the new table to reflect the
                // (possibly previously set) flag markers and the "ignore gaps" setting.
                this.redrawIgnoredValueMarkers(ignoreDataGaps);
                this.redrawEnabledFlagMarkers();
            }
            // Either we're interpreting some pre-processed data sets from a server response,
            // or we're interpreting the data table we just laid out above,
            // which involves skipping disabled rows or columns, optionally ignoring blank values, etc.
            this.interpretDataTable();
            // Start a delay timer that redraws the graph from the interpreted data.
            // This is rather resource intensive, so we're delaying a bit, and restarting the delay
            // if the user makes additional edits to the data within the delay period.
            this.queueGraphRemake();
            this.nextStepCallback();
        }


        // TODO: Get rid of the magic numbers used here.
        figureOutThisRowsDataType(mode: string, label: string, row: string[]): number {
            var blank: number, strings: number, condensed: string[];
            if (mode == 'tr') {
                if (label.match(/gene/i)) {
                    return TypeEnum.Gene_Names;
                }
                if (label.match(/rpkm/i)) {
                    return TypeEnum.RPKM_Values;
                }
                // If we can't match to the above two, set the row to 'undefined' so it's ignored by default
                return 0;
            }
            // Take care of some braindead guesses
            if (label.match(/assay/i) || label.match(/line/i)) {
                return TypeEnum.Assay_Line_Names;
            }
            if (mode == 'pr') {
                if (label.match(/protein/i)) {
                    return TypeEnum.Protein_Name;
                }
                // No point in continuing, only line and protein are relevant
                return 0;
            }
            // Things we'll be counting to hazard a guess at the row contents
            blank = strings = 0;
            // A condensed version of the row, with no nulls or blank values
            condensed = row.filter((v: string): boolean => !!v);
            blank = row.length - condensed.length;
            condensed.forEach((v: string): void => {
                v = v.replace(/,/g, '');
                if (isNaN(parseFloat(v))) {
                    ++strings;
                }
            });
            // If the label parses into a number and the data contains no strings, call it a timsetamp for data
            if (!isNaN(parseFloat(label)) && (strings === 0)) {
                return TypeEnum.Timestamp;
            }
            // No choice by default
            return 0;
        }


        inferActiveFlags(grid:any):void {
            // An important thing to note here is that this data is in [y][x] format -
            // that is, it goes by row, then by column, when referencing.
            // This matches Grid.data and Table.dataCells.
            var x: number, y: number;

            (grid[0] || []).forEach((_, x: number): void => {
                if (this.activeColFlags[x] === undefined) {
                    this.activeColFlags[x] = true;
                }
            });
            grid.forEach((row: string[], y: number): void => {
                if (this.activeRowFlags[y] === undefined) {
                    this.activeRowFlags[y] = true;
                }
                this.activeFlags[y] = this.activeFlags[y] || [];
                row.forEach((_, x: number) => {
                    if (this.activeFlags[y][x] === undefined) {
                        this.activeFlags[y][x] = true;
                    }
                });
            });
        }


        constructDataTable(mode:string, grid:any, gridRowMarkers:any): void {
            var controlCols: string[], pulldownOptions: RowPulldownOption[],
                table: HTMLTableElement, colgroup: JQuery, body: HTMLTableElement,
                row: HTMLTableRowElement;

            this.dataCells = [];
            this.colCheckboxCells = [];
            this.colObjects = [];
            this.rowLabelCells = [];
            this.rowCheckboxCells = [];
            controlCols = ['checkbox', 'pulldown', 'label'];
            if (mode === 'tr') {
                pulldownOptions = [
                    ['--', 0],
                    ['Entire Row Is...', [
                            ['Gene Names', TypeEnum.Gene_Names],
                            ['RPKM Values', TypeEnum.RPKM_Values]
                        ]
                    ]
                ];
            } else if (mode === 'pr') {
                pulldownOptions = [
                    ['--', 0],
                    ['Entire Row Is...', [
                            ['Assay/Line Names', TypeEnum.Assay_Line_Names],
                        ]
                    ],
                    ['First Column Is...', [
                            ['Protein Name', TypeEnum.Protein_Name]
                        ]
                    ]
                ];
            } else {
                pulldownOptions = [
                    ['--', 0],
                    ['Entire Row Is...', [
                            ['Assay/Line Names', TypeEnum.Assay_Line_Names],
                            ['Metabolite Names', TypeEnum.Metabolite_Names]
                        ]
                    ],
                    ['First Column Is...', [
                            ['Timestamp', TypeEnum.Timestamp],
                            ['Metadata Name', TypeEnum.Metadata_Name],
                            ['Metabolite Name', TypeEnum.Metabolite_Name]
                        ]
                    ]
                ];
            }

            // attach all event handlers to the table itself
            var t = this;
            table = <HTMLTableElement>$('<table>').attr('cellspacing', '0').appendTo($('#dataTableDiv'))
                .on('click', '[name=enableColumn]', (ev: JQueryMouseEventObject) => {
                    t.toggleTableColumn(ev.target);
                }).on('click', '[name=enableRow]', (ev: JQueryMouseEventObject) => {
                    t.toggleTableRow(ev.target);
                }).on('change', '.pulldownCell > select', (ev: JQueryInputEventObject) => {
                    var targ: JQuery = $(ev.target);
                    t.changedRowDataTypePulldown(
                        parseInt(targ.attr('i'), 10), parseInt(targ.val(), 10));
                })[0];
            // One of the objects here will be a column group, with col objects in it.
            // This is an interesting twist on DOM behavior that you should probably google.
            colgroup = $('<colgroup>').appendTo(table);
            body = <HTMLTableElement>$('<tbody>').appendTo(table)[0];
            // Start with three columns, for the checkboxes, pulldowns, and labels.
            // (These will not be tracked in Table.colObjects.)
            controlCols.forEach((): void => {
                $('<col>').appendTo(colgroup);
            });
            // add col elements for each data column
            (grid[0] || []).forEach((): void => {
                this.colObjects.push($('<col>').appendTo(colgroup)[0]);
            });
            // First row: spacer cells, followed by checkbox cells for each data column
            row = <HTMLTableRowElement>body.insertRow();
            // spacer cells have x and y set to 0 to remove from highlight grid
            controlCols.forEach((): void => {
                $(row.insertCell()).attr({ 'x': '0', 'y': 0 });
            });
            (grid[0] || []).forEach((_, i: number): void => {
                var cell: JQuery, box: JQuery;
                cell = $(row.insertCell()).attr({ 'id': 'colCBCell' + i, 'x': 1 + i, 'y': 0 })
                    .addClass('checkBoxCell');
                box = $('<input type="checkbox"/>').appendTo(cell)
                    .val(i.toString())
                    .attr({ 'id': 'enableColumn' + i, 'name': 'enableColumn' })
                    .prop('checked', this.activeColFlags[i]);
                this.colCheckboxCells.push(cell[0]);
            });
            this.pulldownObjects = [];  // We don't want any lingering old objects in this
            // The rest of the rows: A pulldown, a checkbox, a row label, and a row of data.
            grid.forEach((values: string[], i: number): void => {
                var cell: JQuery;
                row = <HTMLTableRowElement>body.insertRow();
                // checkbox cell
                cell = $(row.insertCell()).addClass('checkBoxCell')
                    .attr({ 'id': 'rowCBCell' + i, 'x': 0, 'y': i + 1 });
                $('<input type="checkbox"/>')
                    .attr({ 'id': 'enableRow' + i, 'name': 'enableRow', })
                    .val(i.toString())
                    .prop('checked', this.activeRowFlags[i])
                    .appendTo(cell);
                this.rowCheckboxCells.push(cell[0]);
                // pulldown cell
                cell = $(row.insertCell()).addClass('pulldownCell')
                    .attr({ 'id': 'rowPCell' + i, 'x': 0, 'y': i + 1 });
                // use existing setting, or use the last if rows.length > settings.length, or blank
                this.pulldownSettings[i] = this.pulldownSettings[i]
                    || this.pulldownSettings.slice(-1)[0] || 0
                this.populatePulldown(
                    cell = $('<select>')
                        .attr({ 'id': 'row' + i + 'type', 'name': 'row' + i + 'type', 'i': i })
                        .appendTo(cell),
                    pulldownOptions,
                    this.pulldownSettings[i]
                );
                this.pulldownObjects.push(cell[0]);
                // label cell
                cell = $(row.insertCell()).attr({ 'id': 'rowMCell' + i, 'x': 0, 'y': i + 1 });
                $('<div>').text(gridRowMarkers[i]).appendTo(cell);
                this.rowLabelCells.push(cell[0]);
                // the table data itself
                this.dataCells[i] = [];
                values.forEach((value: string, x: number): void => {
                    var short: string;
                    value = short = value || '';
                    if (value.length > 32) {
                        short = value.substr(0, 31) + '…';
                    }
                    cell = $(row.insertCell()).attr({
                        'id': 'valCell' + x + '-' + i,
                        'x': x + 1,
                        'y': i + 1,
                        'title': value,
                        'isblank': value === '' ? 1 : undefined
                    });
                    $('<div>').text(short).appendTo(cell);
                    this.dataCells[i].push(cell[0]);
                });
            });
            this.applyTableDataTypeStyling(grid);
        }


        // A recursive function to populate a pulldown with optional optiongroups,
        // and a default selection
        populatePulldown(select:JQuery, options:RowPulldownOption[], value:number):void {
            options.forEach((option: RowPulldownOption): void => {
                if (typeof option[1] === 'number') {
                    $('<option>').text(option[0]).val(option[1])
                        .prop('selected', option[1] === value)
                        .appendTo(select);
                } else {
                    this.populatePulldown(
                        $('<optgroup>').attr('label', option[0]).appendTo(select),
                        option[1], value);
                }
            });
        }


        // This routine does a bit of additional styling to the Step 3 data table.
        // It removes and re-adds the dataTypeCell css classes according to the pulldown settings for each row.
        applyTableDataTypeStyling(grid:any):void {

            grid.forEach((row: string[], index: number): void => {
                var pulldown: number, hlLabel: boolean, hlRow: boolean;
                pulldown = this.pulldownSettings[index] || 0;
                hlLabel = hlRow = false;
                if (pulldown === TypeEnum.Assay_Line_Names || pulldown === TypeEnum.Metabolite_Names) {
                    hlRow = true;
                } else if ( pulldown !== TypeEnum.Timestamp &&
                            pulldown !== TypeEnum.Metadata_Name &&
                            pulldown !== TypeEnum.Metabolite_Name) {
                    hlLabel = true;
                }
                $(this.rowLabelCells[index]).toggleClass('dataTypeCell', hlLabel);
                row.forEach((_, col: number): void => {
                    $(this.dataCells[index][col]).toggleClass('dataTypeCell', hlRow);
                });
            });
        }


        redrawIgnoredValueMarkers(ignoreDataGaps:boolean): void {
            this.dataCells.forEach((row: HTMLElement[]): void => {
                row.forEach((cell: HTMLElement): void => {
                    var toggle: boolean = !ignoreDataGaps && !!cell.getAttribute('isblank');
                    $(cell).toggleClass('ignoredLine', toggle);
                });
            });
        }


        redrawEnabledFlagMarkers():void {
            this.dataCells.forEach((row: HTMLElement[], y: number): void => {
                var toggle: boolean = !this.activeRowFlags[y];
                $(this.rowLabelCells[y]).toggleClass('disabledLine', toggle);
                row.forEach((cell: HTMLElement, x: number): void => {
                    toggle = !this.activeFlags[y][x]
                        || !this.activeColFlags[x]
                        || !this.activeRowFlags[y];
                    $(cell).toggleClass('disabledLine', toggle);
                });
            });
            this.colCheckboxCells.forEach((box: HTMLElement, x: number): void => {
                var toggle: boolean = !this.activeColFlags[x];
                $(box).toggleClass('disabledLine', toggle);
            });
        }


        changedRowDataTypePulldown(index: number, value: number):void {
            var selected: number;

            var grid = this.rawInputStep.getGrid();

            // The value does not necessarily match the selectedIndex.
            selected = this.pulldownObjects[index].selectedIndex;
            this.pulldownSettings[index] = value;
            this.pulldownUserChangedFlags[index] = true;
            if (    value === TypeEnum.Timestamp ||
                    value === TypeEnum.Metadata_Name ||
                    value === TypeEnum.Metabolite_Name ||
                    value === TypeEnum.Protein_Name) {
                // "Timestamp", "Metadata", or other single-table-cell types
                // Set all the rest of the pulldowns to this,
                // based on the assumption that the first is followed by many others
                this.pulldownObjects.slice(index + 1).every(
                    (pulldown: HTMLSelectElement): boolean => {
                        var select: JQuery, i: number;
                        select = $(pulldown);
                        i = parseInt(select.attr('i'), 10);
                        if (this.pulldownUserChangedFlags[i]
                            && this.pulldownSettings[i] !== 0) {
                            return false; // false for break
                        }
                        select.val(value.toString());
                        this.pulldownSettings[i] = value;
                        return true;
                    });
                // In addition to the above action, we also need to do some checking on the entire set of
                // pulldowns, to enforce a division between the "Metabolite Name" single data type and the
                // other single data types. If the user uses even one "Metabolite Name" pulldown, we can't
                // allow any of the other types, and vice-versa.
                //   Why?  Because "Metabolite Name" is used to label the specific case of a table that
                // does not contain a timestamp on either axis.  In that case, the table is meant to
                // provide data for multiple Measurements and Assays for a single unspecified time point.
                // (That time point is requested later in the UI.)
                //   If we allow a single timestamp row, that creates an inconsistent table that is
                // impossible to interpret.
                //   If we allow a single metadata row, that leaves the metadata unconnected to a specific
                // measurement, meaning that the only valid way to interpret it is as Line metadata.  We
                // could potentially support that, but it would be the only case where data imported on
                // this page does not end up in Assays ... and that case doesn't make much sense given
                // that this is the Assay Data Import page!
                //   Anyway, here we run through the pulldowns, making sure that if the user selected
                // "Metabolite Name", we blank out all references to "Timestamp" and "Metadata", and
                // vice-versa.
                grid.forEach((_, i: number): void => {
                    var c: number = this.pulldownSettings[i];
                    if (value === TypeEnum.Metabolite_Name) {
                        if (c === TypeEnum.Timestamp || c === TypeEnum.Metadata_Name) {
                            this.pulldownObjects[i].selectedIndex = 0;
                            this.pulldownSettings[i] = 0;
                        } else if (c === TypeEnum.Metabolite_Names) { // Can't allow "Measurement Types" setting either
                            this.pulldownObjects[i].selectedIndex = TypeEnum.Assay_Line_Names;
                            this.pulldownSettings[i] = TypeEnum.Assay_Line_Names;
                        }
                    } else if ((value === TypeEnum.Timestamp || value === TypeEnum.Metadata_Name) && c === TypeEnum.Metabolite_Name) {
                        this.pulldownObjects[i].selectedIndex = 0;
                        this.pulldownSettings[i] = 0;
                    }
                });
                // It would seem logical to require a similar check for "Protein Name", but in practice
                // the user is disallowed from selecting any of the other single-table-cell types when the
                // page is in Proteomics mode.  So the check is redundant.
            }
            this.applyTableDataTypeStyling(grid);
            this.interpretDataTable();
            this.queueGraphRemake();
            this.nextStepCallback();
        }


        toggleTableRow(box: Element):void {
            var value: number, input: JQuery;
            input = $(box);
            value = parseInt(input.val(), 10);
            this.activeRowFlags[value] = input.prop('checked');
            this.interpretDataTable();
            this.redrawEnabledFlagMarkers();
            // Resetting a disabled row may change the number of rows listed in the Info table.
            this.queueGraphRemake();
            this.nextStepCallback();
        }


        toggleTableColumn(box: Element):void {
            var value: number, input: JQuery;
            input = $(box);
            value = parseInt(input.val(), 10);
            this.activeColFlags[value] = input.prop('checked');
            this.interpretDataTable();
            this.redrawEnabledFlagMarkers();
            // Resetting a disabled column may change the rows listed in the Info table.
            this.queueGraphRemake();
            this.nextStepCallback();
        }


        resetEnabledFlagMarkers():void {

            var grid = this.rawInputStep.getGrid();

            grid.forEach((row: string[], y: number): void => {
                this.activeFlags[y] = this.activeFlags[y] || [];
                row.forEach((_, x: number): void => {
                    this.activeFlags[y][x] = true;
                });
                this.activeRowFlags[y] = true;
            });
            (grid[0] || []).forEach((_, x: number): void => {
                this.activeColFlags[x] = true;
            });
            // Flip all the checkboxes on in the header cells for the data columns
            $('#dataTableDiv').find('[name=enableColumn]').prop('checked', true);
            // Same for the checkboxes in the row label cells
            $('#dataTableDiv').find('[name=enableRow]').prop('checked', true);
            this.interpretDataTable();
            this.redrawEnabledFlagMarkers();
            this.queueGraphRemake();
            this.nextStepCallback();
        }


        interpretDataTable():void {

            // This mode means we make a new "set" for each cell in the table, rather than
            // the standard method of making a new "set" for each column in the table.
            var singleMode:boolean;
            var single: number, nonSingle: number, earliestName: number;

            var grid = this.rawInputStep.getGrid();
            var gridRowMarkers = this.rawInputStep.gridRowMarkers;
            var ignoreDataGaps = this.rawInputStep.ignoreDataGaps;

            // We'll be accumulating these for disambiguation.
            var seenLineNames:{[id:string]: boolean} = {};
            var seenAssayNames:{[id:string]: boolean} = {};
            var seenMeasurementNames:{[id:string]: boolean} = {};
            var seenMetadataNames:{[id:string]: boolean} = {};

            // Here are the arrays we will use later
            this.parsedSets = [];
            this.graphSets = [];

            this.uniqueLineNames = [];
            this.uniqueAssayNames = [];
            this.uniqueMeasurementNames = [];
            this.uniqueMetadataNames = [];
            this.seenAnyTimestamps = false;

            // If we've got pre-processed sets from the server available, use those instead of any
            // table contents.

            if (this.rawInputStep.processedSetsAvailable) {

                this.rawInputStep.processedSetsFromFile.forEach((rawSet, c: number): void => {
                    var set: RawImportSet, graphSet: GraphingSet, uniqueTimes: number[], times: any, foundMeta: boolean;

                    var ln = rawSet.line_name;
                    var an = rawSet.assay_name;
                    var mn = rawSet.measurement_name;

                    uniqueTimes = [];
                    times = {};
                    foundMeta = false;

                    // The procedure for Assays, Measurements, etc is the same:
                    // If the value is blank, we can't build a valid set, so skip to the next set.
                    // If the value is valid but we haven't seen it before, increment and store a uniqueness index.
                    if (!ln && ln !== 0) { return; }
                    if (!an && an !== 0) { return; }
                    if (!mn && mn !== 0) { return; }
                    if (!seenLineNames[ln]) {
                        seenLineNames[ln] = true;
                        this.uniqueLineNames.push(ln);
                    }
                    if (!seenAssayNames[an]) {
                        seenAssayNames[an] = true;
                        this.uniqueAssayNames.push(an);
                    }
                    if (!seenMeasurementNames[mn]) {
                        seenMeasurementNames[mn] = true;
                        this.uniqueMeasurementNames.push(mn);
                    }

                    var reassembledData = [];

                    // Slightly different procedure for metadata, but same idea:
                    Object.keys(rawSet.metadata_by_name).forEach((key):void => {
                        var value = rawSet.metadata_by_name[key];
                        if (!seenMetadataNames[key]) {
                            seenMetadataNames[key] = true;
                            this.uniqueMetadataNames.push(key);
                        }
                        foundMeta = true;
                    });

                    // Validate the provided set of time/value points
                    rawSet.data.forEach((xy: string[]): void => {
                        var time = xy[0] || '';
                        var value = xy[1];
                        // Sometimes people - or Excel docs - drop commas into large numbers.
                        var timeFloat = parseFloat(time.replace(/,/g, ''));
                        // If we can't get a usable timestamp, discard this point.
                        if (isNaN(timeFloat)) { return; }
                        if (!value && <any>value !== 0) {
                            // If we're ignoring gaps, skip any undefined/null values.
                            //if (ignoreDataGaps) { return; }    // Note: Forced always-off for now
                            // A null is our standard placeholder value
                            value = null;
                        }
                        if (!times[timeFloat]) {
                            times[timeFloat] = value;
                            uniqueTimes.push(timeFloat);
                            this.seenAnyTimestamps = true;
                        }
                    });
                    uniqueTimes.sort((a, b) => a - b).forEach((time: number): void => {
                        reassembledData.push([time, times[time]]);
                    });

                    // Only save if we accumulated some data or metadata
                    if (!uniqueTimes.length && !foundMeta) { return; }

                    set = {
                        // Copy across the fields from the RawImportSet record
                        kind:              rawSet.kind,
                        line_name:         rawSet.line_name,
                        assay_name:        rawSet.assay_name,
                        measurement_name:  rawSet.measurement_name,
                        metadata_by_name:  rawSet.metadata_by_name,
                        data:              reassembledData
                    };
                    this.parsedSets.push(set);

                    graphSet = {
                        'label': (ln ? ln+': ' : '') + an+': ' + mn,
                        'name': mn,
                        'units': 'units',
                        'data': reassembledData
                    }
                    this.graphSets.push(graphSet);
                });
                return;
            }

            // If we're not using pre-processed records, we need to use the pulldown settings in this step
            // (usually set by the user) to determine what mode we're in.

            single = 0;
            nonSingle = 0;
            earliestName = null;
            // Look for the presence of "single measurement type" rows, and rows of all other single-item types
            grid.forEach((_, y: number): void => {
                var pulldown: number;
                if (this.activeRowFlags[y]) {
                    pulldown = this.pulldownSettings[y];
                    if (pulldown === TypeEnum.Metabolite_Name || pulldown === TypeEnum.Protein_Name) {
                        single++; // Single Measurement Name or Single Protein Name
                    } else if (pulldown === TypeEnum.Metadata_Name || pulldown === TypeEnum.Timestamp) {
                        nonSingle++;
                    } else if (pulldown === TypeEnum.Assay_Line_Names && earliestName === null) {
                        earliestName = y;
                    }
                }
            });

            // Only use this mode if the table is entirely free of single-timestamp and
            // single-metadata rows, and has at least one "single measurement" row, and at
            // least one "Assay/Line names" row.
            // (Note that requirement of an "Assay/Line names" row prevents this mode from being
            // enabled when the page is in 'Transcriptomics' or 'Proteomics' mode.)
            singleMode = (single > 0 && nonSingle === 0 && earliestName !== null) ? true : false;

            // A "set" for every cell of the table, with the timestamp to be determined later.
            if (singleMode) {

                this.colObjects.forEach((_, c: number): void => {
                    var cellValue: string, set: RawImportSet;

                    if (!this.activeColFlags[c]) { return; }
                    cellValue = grid[earliestName][c] || '';
                    if (!cellValue) { return; }

                    // If haven't seen cellValue before, increment and store uniqueness index
                    if (!seenAssayNames[cellValue]) {
                        seenAssayNames[cellValue] = true;
                        this.uniqueAssayNames.push(cellValue);
                    }
                    grid.forEach((row: string[], r: number): void => {
                        var pulldown: number, label: string, value: string, timestamp: number;
                        if (!this.activeRowFlags[r] || !this.activeFlags[r][c]) {
                            return;
                        }
                        pulldown = this.pulldownSettings[r];
                        label = gridRowMarkers[r] || '';
                        value = row[c] || '';
                        if (!pulldown || !label || !value) { return; }

                        var m_name:string = null;
                        if (pulldown === TypeEnum.Metabolite_Name) {
                            if (!seenMeasurementNames[label]) {
                                seenMeasurementNames[label] = true;
                                this.uniqueMeasurementNames.push(label);
                            }
                            m_name = label;
                        } else if (pulldown === TypeEnum.Protein_Name) {
                            m_name = label;
                        } else {
                            // If we aren't on a row that's labeled as either a metabolite valye or a protein value,
                            // return without making a set.
                            return;
                        }

                        set = {
                            kind:              this.selectMajorKindStep.interpretationMode,
                            line_name:         null,
                            assay_name:        cellValue,
                            measurement_name:  m_name,
                            metadata_by_name:  {},
                            data:              [[null, value]]
                        };
                        this.parsedSets.push(set);
                    });
                });
                return;
            }

            // The standard method: Make a "set" for each column of the table

            this.colObjects.forEach((_, c: number): void => {
                var set: RawImportSet, graphSet: GraphingSet, uniqueTimes: number[], times: any, foundMeta: boolean;
                // Skip it if the whole column is deactivated
                if (!this.activeColFlags[c]) {
                    return;
                }

                var reassembledData = [];    // We'll fill this out as we go

                set = {
                    kind:              this.selectMajorKindStep.interpretationMode,
                    line_name:         null,
                    assay_name:        null,
                    measurement_name:  null,
                    metadata_by_name:  {},
                    data:              reassembledData,
                };

                uniqueTimes = [];
                times = {};
                foundMeta = false;
                grid.forEach((row: string[], r: number): void => {
                    var pulldown: number, label: string, value: string, timestamp: number;
                    if (!this.activeRowFlags[r] || !this.activeFlags[r][c]) {
                        return;
                    }
                    pulldown = this.pulldownSettings[r];
                    label = gridRowMarkers[r] || '';
                    value = row[c] || '';
                    if (!pulldown) {
                        return;
                    } else if (pulldown === TypeEnum.RPKM_Values) {  // Transcriptomics: RPKM values
                        value = value.replace(/,/g, '');
                        if (value) {
                            reassembledData = [[null, value]];
                        }
                        return;
                    } else if (pulldown === TypeEnum.Gene_Names) {  // Transcriptomics: Gene names
                        if (value) {
                            set.measurement_name = value;
                        }
                        return;
                    } else if (pulldown === TypeEnum.Timestamp) {   // Timestamps
                        label = label.replace(/,/g, '');
                        timestamp = parseFloat(label);
                        if (!isNaN(timestamp)) {
                            if (!value) {
                                // If we're ignoring gaps, skip out on recording this value
                                if (ignoreDataGaps) {
                                    return;
                                }
                                // We actually prefer null here, to indicate a placeholder value
                                value = null;
                            }
                            if (!times[timestamp]) {
                                times[timestamp] = value;
                                uniqueTimes.push(timestamp);
                                this.seenAnyTimestamps = true;
                            }
                        }
                        return;
                    } else if (label === '' || value === '') {
                        // Now that we've dealt with timestamps, we proceed on to other data types.
                        // All the other data types do not accept a blank value, so we weed them out now.
                        return;
                    } else if (pulldown === TypeEnum.Assay_Line_Names) {
                        // If haven't seen value before, increment and store uniqueness index
                        if (!seenAssayNames[value]) {
                            seenAssayNames[value] = true;
                            this.uniqueAssayNames.push(value);
                        }
                        set.assay_name = value;
                        return;
                    } else if (pulldown === TypeEnum.Metabolite_Names) {   // Metabolite Names
                        // If haven't seen value before, increment and store uniqueness index
                        if (!seenMeasurementNames[value]) {
                            seenMeasurementNames[value] = true;
                            this.uniqueMeasurementNames.push(value);
                        }
                        set.measurement_name = value;
                        return;
                    } else if (pulldown === TypeEnum.Metadata_Name) {   // Metadata
                        if (!seenMetadataNames[label]) {
                            seenMetadataNames[label] = true;
                            this.uniqueMetadataNames.push(label);
                        }
                        set.metadata_by_name[label] = value;
                        foundMeta = true;
                    }
                });
                uniqueTimes.sort((a, b) => a - b).forEach((time: number): void => {
                    reassembledData.push([time, times[time]]);
                });
                // only save if accumulated some data or metadata
                if (!uniqueTimes.length && !foundMeta && !reassembledData[0]) {
                    return;
                }

                this.parsedSets.push(set);

                graphSet = {
                    'label': 'Column ' + c,
                    'name': 'Column ' + c,
                    'units': 'units',
                    'data': reassembledData
                }
                this.graphSets.push(graphSet);
            });
        }


        highlighterF(e: JQueryMouseEventObject):void {
            var cell: JQuery, x: number, y: number;
            // Walk up the item tree until we arrive at a table cell,
            // so we can get the index of the table cell in the table.
            cell = $(e.target).closest('td');
            if (cell.length) {
                x = parseInt(cell.attr('x'), 10);
                y = parseInt(cell.attr('y'), 10);
                if (x) {
                    $(this.colObjects[x - 1]).toggleClass('hoverLines', e.type === 'mouseover');
                }
                if (y) {
                    cell.closest('tr').toggleClass('hoverLines', e.type === 'mouseover');
                }
            }
        }


        singleValueDisablerF(e: JQueryMouseEventObject):void {
            var cell: JQuery, x: number, y: number;
            // Walk up the item tree until we arrive at a table cell,
            // so we can get the index of the table cell in the table.
            cell = $(e.target).closest('td');
            if (!cell.length) { return; }
            x = parseInt(cell.attr('x'), 10);
            y = parseInt(cell.attr('y'), 10);
            if (!x || !y || x < 1 || y < 1) { return; }
            --x;
            --y;
            if (this.activeFlags[y][x]) {
                this.activeFlags[y][x] = false;
            } else {
                this.activeFlags[y][x] = true;
            }
            this.interpretDataTable();
            this.redrawEnabledFlagMarkers();
            this.queueGraphRemake();
            this.nextStepCallback();
        }


        queueGraphRemake():void {
            // Start a timer to wait before calling the routine that remakes the graph.
            // This way we're not bothering the user with the long redraw process when
            // they are making fast edits.
            if (this.graphRefreshTimerID) {
                clearTimeout(this.graphRefreshTimerID);
            }
            if (this.graphEnabled) {
                this.graphRefreshTimerID = setTimeout(this.remakeGraphArea.bind(this), 700);
            }
        }


        remakeGraphArea():void {

            var mode = this.selectMajorKindStep.interpretationMode;

            this.graphRefreshTimerID = 0;
            if (!EDDATDGraphing || !this.graphEnabled) {
                return;
            }
            EDDATDGraphing.clearAllSets();
            var sets = this.graphSets;
            // If we're not in either of these modes, drawing a graph is nonsensical.
            if (mode === "std" || mode === 'biolector') {
                sets.forEach((set) => EDDATDGraphing.addNewSet(set));
            }
            EDDATDGraphing.drawSets();
        }
    }



    interface AutoCache {
        comp: any,
        meta: any,
        unit: any,
        metabolite: any
    }


    // The class responsible for everything in the "Step 4" box that you see on the data import page.
    export class TypeDisambiguationStep {

        identifyStructuresStep: IdentifyStructuresStep;

        // These objects hold string keys that correspond to unique names found during parsing.
        // The string keys point to existing autocomplete objects created specifically for
        // those strings.  Any selections the user has already set will be preserved,
        // even as the disambiguation section is destroyed and remade.

        protocolCurrentlyDisplayed: number;
        // For disambuguating Lines
        lineObjSets: any;
        currentlyVisibleLineObjSets: any[];
        // For disambuguating Assays (really Assay/Line combinations)
        assayObjSets: any;
        currentlyVisibleAssayObjSets: any[];
        // For disambuguating measurement types
        measurementObjSets: any;
        currentlyVisibleMeasurementObjSets: any[];
        // For disambuguating metadata
        metadataObjSets: any;
        // To give unique ID values to each autocomplete entity we create
        autoCompUID: number;

        autoCache: AutoCache;

        selectMajorKindStep: SelectMajorKindStep;
        nextStepCallback: any;


        constructor(selectMajorKindStep: SelectMajorKindStep, identifyStructuresStep: IdentifyStructuresStep, nextStepCallback: any) {

            this.lineObjSets = {};
            this.assayObjSets = {};
            this.currentlyVisibleLineObjSets = [];
            this.currentlyVisibleAssayObjSets = [];
            this.measurementObjSets = {};
            this.currentlyVisibleMeasurementObjSets = [];
            this.metadataObjSets = {};
            this.autoCompUID = 0;
            this.protocolCurrentlyDisplayed = 0;

            this.autoCache = {
                comp: {},
                meta: {},
                unit: {},
                metabolite: {}
            };

            this.selectMajorKindStep = selectMajorKindStep;
            this.identifyStructuresStep = identifyStructuresStep;
            this.nextStepCallback = nextStepCallback;

            var reDoStepOnChange = ['#masterAssay', '#masterLine', '#masterMComp', '#masterMType', '#masterMUnits'];
            $(reDoStepOnChange.join(',')).on('change', this.changedAnyMasterPulldown.bind(this));

            $('#resetstep4').on('click', this.resetDisambiguationFields.bind(this));

            // enable autocomplete on statically defined fields
            EDD_auto.setup_field_autocomplete('#masterMComp', 'MeasurementCompartment');
            EDD_auto.setup_field_autocomplete('#masterMType', 'GenericOrMetabolite', EDDData.MetaboliteTypes || {});
            EDD_auto.setup_field_autocomplete('#masterMUnits', 'MeasurementUnit');
        }


        previousStepChanged(): void {
            var assayIn: JQuery;
            var currentAssays: number[];
            var masterP = this.selectMajorKindStep.masterProtocol;    // Shout-outs to a mid-grade rapper
            if (this.protocolCurrentlyDisplayed != masterP) {
                this.protocolCurrentlyDisplayed = masterP;
                // We deal with recreating this pulldown here, instead of in remakeAssaySection(),
                // because remakeAssaySection() is called by reconfigure(), which is called
                // when other UI in this step changes.  This pulldown is NOT affected by changes to
                // the other UI, so it would be pointless to remake it in response to them.
                assayIn = $('#masterAssay').empty();
                $('<option>').text('(Create New)').appendTo(assayIn).val('new').prop('selected', true);
                currentAssays = ATData.existingAssays[masterP] || [];
                currentAssays.forEach((id: number): void => {
                    var assay = EDDData.Assays[id],
                        line = EDDData.Lines[assay.lid],
                        protocol = EDDData.Protocols[assay.pid];
                    $('<option>').appendTo(assayIn).val('' + id).text([
                        line.name, protocol.name, assay.name].join('-'));
                });
                // Always reveal this, since the default for the Assay pulldown is always 'new'.
                $('#masterLineSpan').removeClass('off');
            }
            this.reconfigure();
        }


        // Create the Step 4 tables:  Sets of rows, one for each y-axis column of values,
        // where the user can fill out additional information for the pasted table.
        reconfigure(): void {
            var mode = this.selectMajorKindStep.interpretationMode;

            var parsedSets = this.identifyStructuresStep.parsedSets;
            var seenAnyTimestamps = this.identifyStructuresStep.seenAnyTimestamps;
            // Hide all the subsections by default
            $('#masterTimestampDiv').addClass('off');
            $('#disambiguateLinesSection').addClass('off');
            $('#masterLineDiv').addClass('off');
            $('#disambiguateAssaysSection').addClass('off');
            $('#masterAssayLineDiv').addClass('off');
            $('#disambiguateMeasurementsSection').addClass('off');
            $('#masterMTypeDiv').addClass('off');
            $('#disambiguateMetadataSection').addClass('off');

            // If no sets to show, leave the area blank and show the 'enter some data!' banner
            if (parsedSets.length === 0) {
                $('#emptyDisambiguationLabel').removeClass('off');
                return;
            }

            $('#emptyDisambiguationLabel').addClass('off');
            // If parsed data exists, but we haven't seen a single timestamp, show the "master timestamp" UI.
            $('#masterTimestampDiv').toggleClass('off', seenAnyTimestamps);
            // Call subroutines for each of the major sections
            if (mode === "biolector") {
                this.remakeLineSection();
            } else {
                this.remakeAssaySection();
            }
            this.remakeMeasurementSection();
            this.remakeMetadataSection();
            this.nextStepCallback();
        }


        // TODO: This function should reset all the disambiguation fields to the values
        // that were auto-detected in the last refresh of the object.
        resetDisambiguationFields(): void {
            // Get to work!!
        }


        // If the previous step found Line names that need resolving, and the interpretation mode in Step 1
        // warrants resolving Lines independent of Assays, we create this section.
        // The point is that if we connect unresolved Line strings on their own, the unresolved Assay strings
        // can be used to create multiple new Assays with identical names under a range of Lines.
        // This means users can create a matrix of Line/Assay combinations, rather than a one-dimensional
        // resolution where unique Assay names must always point to one unique Assay record.
        remakeLineSection(): void {
            var table: HTMLTableElement, body: HTMLTableElement;
            var uniqueLineNames = this.identifyStructuresStep.uniqueLineNames;

            this.currentlyVisibleLineObjSets.forEach((disam:any): void => {
                disam.rowElementJQ.detach();
            });
            $('#disambiguateLinesTable').remove();

            if (uniqueLineNames.length === 0) {
                $('#masterLineDiv').removeClass('off');
                return;
            }

            this.currentlyVisibleLineObjSets = [];
            var t = this;
            table = <HTMLTableElement>$('<table>')
                .attr({ 'id': 'disambiguateLinesTable', 'cellspacing': 0 })
                .appendTo($('#disambiguateLinesSection').removeClass('off'))
                .on('change', 'select', (ev: JQueryInputEventObject): void => {
                    t.userChangedLineDisam(ev.target);
                })[0];
            body = <HTMLTableElement>$('<tbody>').appendTo(table)[0];
            uniqueLineNames.forEach((name: string, i: number): void => {
                var disam: any, row: HTMLTableRowElement, defaultSel: any, cell: JQuery, select: JQuery;
                disam = this.lineObjSets[name];
                if (!disam) {
                    disam = {};
                    defaultSel = this.disambiguateAnAssayOrLine(name, i);
                    // First make a table row, and save a reference to it
                    row = <HTMLTableRowElement>body.insertRow();
                    disam.rowElementJQ = $(row);
                    // Next, add a table cell with the string we are disambiguating
                    $('<div>').text(name).appendTo(row.insertCell());
                    // Now build another table cell that will contain the pulldowns
                    cell = $(row.insertCell()).css('text-align', 'left');
                    select = $('<select>').appendTo(cell)
                        .data({ 'setByUser': false })
                        .attr('name', 'disamLine' + i);
                    disam.selectLineJQElement = select;
                    $('<option>').text('(Create New)').appendTo(select).val('new')
                        .prop('selected', !defaultSel.lineID);
                    (ATData.existingLines || []).forEach((line: any): void => {
                        $('<option>').text(line.n)
                            .appendTo(select).val(line.id.toString())
                            .prop('selected', defaultSel.lineID === line.id);
                    });
                    this.lineObjSets[name] = disam;
                }
                disam.selectLineJQElement.data({ 'visibleIndex': i });
                disam.rowElementJQ.appendTo(body);
                this.currentlyVisibleLineObjSets.push(disam);
            });
        }


        // If the previous step found Line or Assay names that need resolving, put together a disambiguation section
        // for Assays/Lines.
        // Keep a separate set of correlations between strings and pulldowns for each Protocol,
        // since the same string can match different Assays, and the pulldowns will have different content, in each Protocol.
        // If the previous step didn't find any Line or Assay names that need resolving,
        // reveal the pulldowns for selecting a master Line/Assay, leaving the table empty, and return.
        remakeAssaySection(): void {
            var table: HTMLTableElement, body: HTMLTableElement;
            var uniqueAssayNames = this.identifyStructuresStep.uniqueAssayNames;
            var masterP = this.protocolCurrentlyDisplayed;

            this.currentlyVisibleAssayObjSets.forEach((disam:any): void => {
                disam.rowElementJQ.detach();
            });

            $('#disambiguateAssaysTable').remove();

            this.assayObjSets[masterP] = this.assayObjSets[masterP] || {};

            if (uniqueAssayNames.length === 0) {
                $('#masterAssayLineDiv').removeClass('off');
                return;
            }

            this.currentlyVisibleAssayObjSets = [];
            var t = this;
            table = <HTMLTableElement>$('<table>')
                .attr({ 'id': 'disambiguateAssaysTable', 'cellspacing': 0 })
                .appendTo($('#disambiguateAssaysSection').removeClass('off'))
                .on('change', 'select', (ev: JQueryInputEventObject): void => {
                    t.userChangedAssayDisam(ev.target);
                })[0];
            body = <HTMLTableElement>$('<tbody>').appendTo(table)[0];
            uniqueAssayNames.forEach((name: string, i: number): void => {
                var disam: any, row: HTMLTableRowElement, defaultSel: any, cell: JQuery, aSelect: JQuery, lSelect: JQuery;
                disam = this.assayObjSets[masterP][name];
                if (!disam) {
                    disam = {};
                    defaultSel = this.disambiguateAnAssayOrLine(name, i);
                    // First make a table row, and save a reference to it
                    row = <HTMLTableRowElement>body.insertRow();
                    disam.rowElementJQ = $(row);
                    // Next, add a table cell with the string we are disambiguating
                    $('<div>').text(name).appendTo(row.insertCell());
                    // Now build another table cell that will contain the pulldowns
                    cell = $(row.insertCell()).css('text-align', 'left');
                    aSelect = $('<select>').appendTo(cell)
                        .data({ 'setByUser': false })
                        .attr('name', 'disamAssay' + i);
                    disam.selectAssayJQElement = aSelect;
                    $('<option>').text('(Create New)').appendTo(aSelect).val('new')
                        .prop('selected', !defaultSel.assayID);
                    (ATData.existingAssays[masterP] || []).forEach((id: number): void => {
                        var assay: AssayRecord, line: LineRecord, protocol: any;
                        assay = EDDData.Assays[id];
                        line = EDDData.Lines[assay.lid];
                        protocol = EDDData.Protocols[assay.pid];
                        $('<option>').text([line.name, protocol.name, assay.name].join('-'))
                            .appendTo(aSelect).val(id.toString())
                            .prop('selected', defaultSel.assayID === id);
                    });
                    // a span to contain the text label for the Line pulldown, and the pulldown itself
                    cell = $('<span>').text('for Line:').toggleClass('off', !!defaultSel.assayID)
                        .appendTo(cell);
                    lSelect = $('<select>').appendTo(cell).data('setByUser', false)
                        .attr('name', 'disamLine' + i);
                    disam.selectLineJQElement = lSelect;
                    $('<option>').text('(Create New)').appendTo(lSelect).val('new')
                        .prop('selected', !defaultSel.lineID);
                    // ATData.existingLines is of type {id: number; n: string;}[]
                    (ATData.existingLines || []).forEach((line: any) => {
                        $('<option>').text(line.n).appendTo(lSelect).val(line.id.toString())
                            .prop('selected', defaultSel.lineID === line.id);
                    });
                    this.assayObjSets[masterP][name] = disam;
                }
                disam.selectAssayJQElement.data({ 'visibleIndex': i });
                disam.rowElementJQ.appendTo(body);
                this.currentlyVisibleAssayObjSets.push(disam);
            });
        }


        remakeMeasurementSection(): void {
            var body: HTMLTableElement, row: HTMLTableRowElement;

            var mode = this.selectMajorKindStep.interpretationMode;
            var uniqueMeasurementNames = this.identifyStructuresStep.uniqueMeasurementNames;
            var seenAnyTimestamps = this.identifyStructuresStep.seenAnyTimestamps;

            $('#disambiguateMeasurementsSection').addClass('off');
            $('#masterMTypeDiv').addClass('off');

            // If in 'Transcription' or 'Proteomics' mode, there are no measurement types involved.
            // skip the measurement section, and provide statistics about the gathered records.
            if (mode === "tr" || mode === "pr") { return; }

            // No measurements for disambiguation, have timestamp data:  That means we need to choose one measurement.
            // You might think that we should display this even without timestamp data, to handle the case where we're importing
            // a single measurement type for a single timestamp...  But that would be a 1-dimensional import, since there is only
            // one other object with multiple types to work with (lines/assays).  We're not going to bother supporting that.
            if (uniqueMeasurementNames.length === 0 && seenAnyTimestamps) {
                $('#masterMTypeDiv').removeClass('off');
                return;
            }

            this.currentlyVisibleMeasurementObjSets.forEach((disam:any): void => {
                disam.rowElementJQ.detach();
            });
            $('#disambiguateMeasurementsSection').removeClass('off');

            // put together a disambiguation section for measurement types
            var t = this;
            body = <HTMLTableElement>($('#disambiguateMeasurementsTable').children().first()[0]);
            this.currentlyVisibleMeasurementObjSets = [];   // For use in cascading user settings
            uniqueMeasurementNames.forEach((name: string, i: number): void => {
                var disam: any;
                disam = this.measurementObjSets[name];
                if (disam && disam.rowElementJQ) {
                    disam.rowElementJQ.appendTo(body);
                } else {
                    disam = {};
                    row = <HTMLTableRowElement>body.insertRow();
                    disam.rowElementJQ = $(row);
                    $('<div>').text(name).appendTo(row.insertCell());
                    ['compObj', 'typeObj', 'unitsObj'].forEach((auto: string): void => {
                        var cell: JQuery = $(row.insertCell()).addClass('disamDataCell');
                        disam[auto] = EDD_auto.create_autocomplete(cell).data('type', auto);
                    });
                    disam.typeHiddenObj = disam.typeObj.attr('size', 45).next();
                    disam.compHiddenObj = disam.compObj.attr('size', 4).next();
                    disam.unitsHiddenObj = disam.unitsObj.attr('size', 10).next();
                    $(row).on('change', 'input[type=hidden]', (ev: JQueryInputEventObject): void => {
                        // only watch for changes on the hidden portion, let autocomplete work
                        t.userChangedMeasurementDisam(ev.target);
                    });
                    EDD_auto.setup_field_autocomplete(disam.compObj, 'MeasurementCompartment', this.autoCache.comp);
                    EDD_auto.setup_field_autocomplete(disam.typeObj, 'GenericOrMetabolite', this.autoCache.metabolite);
                    EDD_auto.initial_search(disam.typeObj, name);
                    EDD_auto.setup_field_autocomplete(disam.unitsObj, 'MeasurementUnit', this.autoCache.unit);
                    this.measurementObjSets[name] = disam;
                }
                // TODO sizing should be handled in CSS
                disam.compObj.data('visibleIndex', i);
                disam.typeObj.data('visibleIndex', i);
                disam.unitsObj.data('visibleIndex', i);
                // If we're in MDV mode, the units pulldowns are irrelevant.
                disam.unitsObj.toggleClass('off', mode === 'mdv');
                this.currentlyVisibleMeasurementObjSets.push(disam);
            });
            this.checkAllMeasurementCompartmentDisam();
        }


        remakeMetadataSection(): void {
            var table: HTMLTableElement, body: HTMLTableElement, row: HTMLTableRowElement;

            var uniqueMetadataNames = this.identifyStructuresStep.uniqueMetadataNames;
            if (uniqueMetadataNames.length < 1) { return; }

            $('#disambiguateMetadataTable').remove();
            // put together a disambiguation section for metadata
            table = <HTMLTableElement>$('<table>')
                .attr({ 'id': 'disambiguateMetadataTable', 'cellspacing': 0 })
                .appendTo($('#disambiguateMetadataSection').removeClass('off'))
                .on('change', 'input', (ev: JQueryInputEventObject): void => {
                    // should there be event handling here ?
                })[0];
            body = <HTMLTableElement>$('<tbody>').appendTo(table)[0];
            uniqueMetadataNames.forEach((name: string, i: number): void => {
                var disam: any;
                disam = this.metadataObjSets[name];
                if (disam && disam.rowElementJQ) {
                    disam.rowElementJQ.appendTo(body);
                } else {
                    disam = {};
                    row = <HTMLTableRowElement>body.insertRow();
                    disam.rowElementJQ = $(row);
                    $('<div>').text(name).appendTo(row.insertCell());
                    disam.metaObj = EDD_auto.create_autocomplete(row.insertCell()).val(name);
                    disam.metaHiddenObj = disam.metaObj.next();
                    this.metadataObjSets[name] = disam;
                }
                disam.metaObj.attr('name', 'disamMeta' + i).addClass('autocomp_altype')
                    .next().attr('name', 'disamMetaHidden' + i);
                EDD_auto.setup_field_autocomplete(disam.metaObj, 'AssayLineMetadataType', this.autoCache.meta);
            });
        }


        // We call this when any of the 'master' pulldowns are changed in Step 4.
        // Such changes may affect the available contents of some of the pulldowns in the step.
        changedAnyMasterPulldown(): void {
            // Show the master line dropdown if the master assay dropdown is set to new
            $('#masterLineSpan').toggleClass('off', $('#masterAssay').val() !== 'new');
            this.reconfigure();
        }


        // If the pulldown is being set to 'new', walk down the remaining pulldowns in the section,
        // in order, setting them to 'new' as well, stopping just before any pulldown marked as
        // being 'set by the user'.
        userChangedLineDisam(lineEl: Element):boolean {
            var changed: JQuery, v: number;
            changed = $(lineEl).data('setByUser', true);
            if (changed.val() !== 'new') {
                // stop here for anything other than 'new'; only 'new' cascades to following pulldowns
                return false;
            }
            v = changed.data('visibleIndex') || 0;
            this.currentlyVisibleLineObjSets.slice(v).forEach((obj: any): void => {
                var select: JQuery = obj.selectLineJQElement;
                if (select.data('setByUser')) {
                    return;
                }
                // set dropdown to 'new' and reveal the line pulldown
                select.val('new').next().removeClass('off');
            });
            return false;
        }


        // This function serves two purposes.
        // 1. If the given Assay disambiguation pulldown is being set to 'new', reveal the adjacent
        //    Line pulldown, otherwise hide it.
        // 2. If the pulldown is being set to 'new', walk down the remaining pulldowns in the section,
        //    in order, setting them to 'new' as well, stopping just before any pulldown marked as
        //    being 'set by the user'.
        userChangedAssayDisam(assayEl: Element):boolean {
            var changed: JQuery, v: number;
            changed = $(assayEl).data('setByUser', true);
            // The span with the corresponding Line pulldown is always right next to the Assay pulldown
            changed.next().toggleClass('off', changed.val() !== 'new');
            if (changed.val() !== 'new') {
                // stop here for anything other than 'new'; only 'new' cascades to following pulldowns
                return false;
            }
            v = changed.data('visibleIndex') || 0;
            this.currentlyVisibleAssayObjSets.slice(v).forEach((obj: any): void => {
                var select: JQuery = obj.selectAssayJQElement;
                if (select.data('setByUser')) {
                    return;
                }
                // set dropdown to 'new' and reveal the line pulldown
                select.val('new').next().removeClass('off');
            });
            return false;
        }


        userChangedMeasurementDisam(element: Element):void {
            console.log('changed');
            var hidden: JQuery, auto: JQuery, type: string, i: number;
            hidden = $(element);
            auto = hidden.prev();
            type = auto.data('type');
            if (type === 'compObj' || type === 'unitsObj') {
                i = auto.data('setByUser', true).data('visibleIndex') || 0;
                this.currentlyVisibleMeasurementObjSets.slice(i).some((obj: any): boolean => {
                    var following: JQuery = $(obj[type]);
                    if (following.length === 0 || following.data('setByUser')) {
                        return true;  // break; for the Array.some() loop
                    }
                    // using placeholder instead of val to avoid triggering autocomplete change
                    following.attr('placeholder', auto.val());
                    following.next().val(hidden.val());
                    return false;
                });
            }
            // not checking typeObj; form submit sends selected types
            this.checkAllMeasurementCompartmentDisam();
        }


        // Run through the list of currently visible measurement disambiguation form elements,
        // checking to see if any of the 'compartment' elements are set to a non-blank value.
        // If any are, and we're in MDV document mode, display a warning that the user should
        // specify compartments for all their measurements.
        checkAllMeasurementCompartmentDisam():void {
            var allSet: boolean;
            var mode = this.selectMajorKindStep.interpretationMode;

            allSet = this.currentlyVisibleMeasurementObjSets.every((obj: any): boolean => {
                var hidden: JQuery = obj.compHiddenObj;
                if (obj.compObj.data('setByUser') || (hidden.val() && hidden.val() !== '0')) {
                    return true;
                }
                return false;
            });
            $('#noCompartmentWarning').toggleClass('off', mode !== 'mdv' || allSet);
        }


        disambiguateAnAssayOrLine(assayOrLine: string, currentIndex: number):any {
            var selections: any, highest: number, assays: number[];
            selections = {
                lineID: 0,
                assayID: 0
            };
            highest = 0;
            // ATData.existingAssays is type {[index: string]: number[]}
            assays = ATData.existingAssays[this.selectMajorKindStep.masterProtocol] || [];
            assays.every((id: number, i: number): boolean => {
                var assay: AssayRecord, line: LineRecord, protocol: any, name: string;
                assay = EDDData.Assays[id];
                line = EDDData.Lines[assay.lid];
                protocol = EDDData.Protocols[assay.pid];
                name = [line.name, protocol.name, assay.name].join('-');
                if (assayOrLine.toLowerCase() === name.toLowerCase()) {
                    // The full Assay name, even case-insensitive, is the best match
                    selections.assayID = id;
                    return false;  // do not need to continue
                } else if (highest < 0.8 && assayOrLine === assay.name) {
                    // An exact-case match with the Assay name fragment alone is second-best.
                    highest = 0.8;
                    selections.assayID = id;
                } else if (highest < 0.7 && assay.name.indexOf(assayOrLine) >= 0) {
                    // Finding the whole string inside the Assay name fragment is pretty good
                    highest = 0.7;
                    selections.assayID = id;
                } else if (highest < 0.6 && line.name.indexOf(assayOrLine) >= 0) {
                    // Finding the whole string inside the originating Line name is good too.
                    // It means that the user may intend to pair with this Assay even though the
                    // Assay name is different.  
                    highest = 0.6;
                    selections.assayID = id;
                } else if (highest < 0.4 &&
                    (new RegExp('(^|\\W)' + assay.name + '(\\W|$)', 'g')).test(assayOrLine)) {
                    // Finding the Assay name fragment within the whole string, as a whole word, is our
                    // last option.
                    highest = 0.4;
                    selections.assayID = id;
                } else if (highest < 0.3 && currentIndex === i) {
                    // If all else fails, choose Assay of current index in sorted order.
                    highest = 0.3;
                    selections.assayID = id;
                }
                return true;
            });
            // Now we repeat the practice, separately, for the Line pulldown.
            highest = 0;
            // ATData.existingLines is type {id: number; n: string;}[]
            (ATData.existingLines || []).every((line: any, i: number): boolean => {
                if (assayOrLine === line.n) {
                    // The Line name, case-sensitive, is the best match
                    selections.lineID = line.id;
                    return false;  // do not need to continue
                } else if (highest < 0.8 && assayOrLine.toLowerCase() === line.n.toLowerCase()) {
                    // The same thing case-insensitive is second best.
                    highest = 0.8;
                    selections.lineID = line.id;
                } else if (highest < 0.7 && assayOrLine.indexOf(line.n) >= 0) {
                    // Finding the Line name within the string is odd, but good.
                    highest = 0.7;
                    selections.lineID = line.id;
                } else if (highest < 0.6 && line.n.indexOf(assayOrLine) >= 0) {
                    // Finding the string within the Line name is also good.
                    highest = 0.6;
                    selections.lineID = line.id;
                } else if (highest < 0.5 && currentIndex === i) {
                    // Again, if all else fails, just choose the Line that matches the current index
                    // in sorted order, in a loop.
                    highest = 0.5;
                    selections.lineID = line.id;
                }
                return true;
            });
            return selections;
        }


        createSetsForSubmission():ResolvedImportSet[] {

            // From Step 1
            var mode = this.selectMajorKindStep.interpretationMode;
            var masterProtocol = $("#masterProtocol").val();

            // From Step 3
            var seenAnyTimestamps = this.identifyStructuresStep.seenAnyTimestamps;
            var parsedSets = this.identifyStructuresStep.parsedSets;

            // From this Step
            var masterTime = parseFloat($('#masterTimestamp').val());
            var masterLine = $('#masterLine').val();
            var masterAssayLine = $('#masterAssayLine').val();
            var masterAssay = $('#masterAssay').val();
            var masterMType = $('#masterMType').val();
            var masterMComp = $('#masterMComp').val();
            var masterMUnits = $('#masterMUnits').val();

            var resolvedSets:ResolvedImportSet[] = [];

            parsedSets.forEach((set, c: number): void => {
                var resolvedSet: ResolvedImportSet;

                var line_id = 'new';    // A convenient default
                var assay_id = 'new';

                var measurement_id = null;
                var compartment_id = null;
                var units_id = null;
                // In modes where we resolve measurement types in the client UI, go with the master values by default.
                if (mode === "biolector" || mode === "std" || mode === "mdv") {
                    measurement_id = masterMType;
                    compartment_id = masterMComp;
                    units_id = masterMUnits;
                }

                var data = set.data;

                var metaData:{[id:string]: string} = {};
                var metaDataPresent:boolean = false;

                if (mode === "biolector") {
                    line_id = masterLine;
                    assay_id = "named_or_new"; // Tells the server to attempt to resolve directly against the name, or make a new Assay
                    // If we have a valid, specific Line name, look for a disambiguation field that matches it.
                    if (set.line_name !== null) {
                        var disam = this.lineObjSets[set.line_name];
                        if (disam) {
                            line_id = disam.selectLineJQElement.val();
                        }
                    }
                } else {
                    line_id = masterAssayLine;
                    assay_id = masterAssay;
                    if (set.assay_name !== null && masterProtocol) {
                        var disam = this.assayObjSets[masterProtocol][set.assay_name];
                        if (disam) {
                            assay_id = disam.selectAssayJQElement.val();
                            line_id = disam.selectLineJQElement.val();
                        }
                    }
                }

                // Same for measurement name, but resolve all three measurement fields if we find a match,
                // and only if we are resolving measurement types client-side.
                if (mode === "biolector" || mode === "std" || mode === "mdv") {
                    if (set.measurement_name !== null) {
                        var disam = this.measurementObjSets[set.measurement_name];
                        if (disam) {
                            measurement_id = disam.typeHiddenObj.val();
                            compartment_id = disam.compHiddenObj.val();
                            units_id = disam.unitsHiddenObj.val();
                        }
                    }
                }

                // Any metadata disambiguation fields that are left unresolved, will have their metadata
                // dropped from the import in this step, because this loop is building key-value pairs where
                // the key is the chosen database id of the metadata type.  No id == not added.
                Object.keys(set.metadata_by_name).forEach((name):void => {
                    var disam = this.metadataObjSets[name];
                    if (disam) {
                        var id = disam.metaHiddenObj.val();
                        if (id) {
                            metaData[id] = set.metadata_by_name[name];
                            metaDataPresent = true;
                        }
                    }
                });

                // If we haven't seen any timestamps during data accumulation, it means we need the user to pick
                // a master timestamp.  In that situation, any given set will have at most one data point in it,
                // with the timestamp in the data point set to 'null'.  Here we resolve it to a valid timestamp.
                // If there is no master timestamp selected, we drop the data point, but make the set anyway since
                // it might carry metadata.
                if (!seenAnyTimestamps && set.data[0]) {
                    if (!isNaN(masterTime)) {
                        data[0][0] = masterTime;
                    } else {
                        data = [];
                    }
                }

                // If we have no data, and no metadata that survived resolving, don't make the set.
                if (data.length < 1 && !metaDataPresent) { return; }

                resolvedSet = {
                    // Copy across the fields from the RawImportSet record
                    kind:              set.kind,
                    line_name:         set.line_name,
                    assay_name:        set.assay_name,
                    measurement_name:  set.measurement_name,
                    metadata_by_name:  set.metadata_by_name,
                    data:              data,
                    // Add new disambiguation-specific fields
                    protocol_id:       masterProtocol,
                    line_id:           line_id,
                    assay_id:          assay_id,
                    measurement_id:    measurement_id,
                    compartment_id:    compartment_id,
                    units_id:          units_id,
                    metadata_by_id:    metaData
                };
                resolvedSets.push(resolvedSet);
            });
            return resolvedSets;
        }
    }
}


$(window).load(function() {
    EDDTableImport.onWindowLoad();
});


