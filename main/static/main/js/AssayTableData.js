/// <reference path="typescript-declarations.d.ts" />
/// <reference path="Utl.ts" />
JSNumber = Number;
JSNumber.isFinite = JSNumber.isFinite || function (value) {
    return typeof value === 'number' && isFinite(value);
};
JSNumber.isNaN = JSNumber.isNaN || function (value) {
    return value !== value;
};
// This module encapsulates all the custom code for the data import page.
// It consists primarily of a series of classes, each corresponding to a step in the import process,
// with a corresponding chunk of UI on the import page.
// Each class pulls data from one or more previous steps, does some internal processing,
// then triggers a callback function, announcing the availability of its own new data.
// The callback function triggers the instance of the next step.
var EDDTableImport;
(function (EDDTableImport) {
    'use strict';
    // Captures important information to be reviewed by the user in the final import step
    var ImportMessage = (function () {
        // update the UI with the result (e.g. by re-querying a REST resource)
        function ImportMessage(message, relatedControlSelector, reevaluateFunction) {
            if (relatedControlSelector === void 0) { relatedControlSelector = null; }
            if (reevaluateFunction === void 0) { reevaluateFunction = null; }
            this.message = message;
            this.relatedControlSelector = relatedControlSelector;
            this.reevaluateFunction = reevaluateFunction;
        }
        return ImportMessage;
    })();
    EDDTableImport.ImportMessage = ImportMessage;
    // As soon as the window load signal is sent, call back to the server for the set of reference records
    // that will be used to disambiguate labels in imported data.
    function onWindowLoad() {
        var atdata_url = "/study/" + EDDData.currentStudyID + "/assaydata";
        $('.disclose').find('a.discloseLink').on('click', EDDTableImport.disclose);
        // Populate ATData and EDDData objects via AJAX calls
        jQuery.ajax(atdata_url, {
            "success": function (data) {
                ATData = data.ATData;
                $.extend(EDDData, data.EDDData);
                EDDTableImport.onReferenceRecordsLoad();
            }
        }).fail(function (x, s, e) {
            alert(s);
        });
    }
    EDDTableImport.onWindowLoad = onWindowLoad;
    // As soon as we've got and parsed the reference data, we can set up all the callbacks for the UI,
    // effectively turning the page "on".
    function onReferenceRecordsLoad() {
        //TODO: clarify reflected GUI state when waiting for large dataset from the server.
        // in several test cases with large #'s of lines, there's time for the user to reach a
        // later / confusing step in the process while waiting on this data to be returned.
        // Probably should fix this in EDD-182.
        $('#waitingForServerLabel').addClass('off');
        // Allocate one instance of each step, providing references to the previous steps as needed.
        var step1 = new SelectMajorKindStep(EDDTableImport.selectMajorKindCallback);
        var step2 = new RawInputStep(step1, EDDTableImport.rawInputCallback, EDDTableImport.processingFileCallback);
        var step3 = new IdentifyStructuresStep(step1, step2, EDDTableImport.identifyStructuresCallback);
        var step4 = new TypeDisambiguationStep(step1, step3, EDDTableImport.typeDisambiguationCallback);
        var step5 = new ReviewStep(step1, step2, step3, step4, EDDTableImport.reviewStepCallback);
        EDDTableImport.selectMajorKindStep = step1;
        EDDTableImport.rawInputStep = step2;
        EDDTableImport.identifyStructuresStep = step3;
        EDDTableImport.typeDisambiguationStep = step4;
        EDDTableImport.reviewStep = step5;
        // Wire up the function that submits the page
        $('#submitForImport').on('click', EDDTableImport.submitForImport);
        // We need to manually trigger this, after all our steps are constructed.
        // This will cascade calls through the rest of the steps and configure them too.
        step1.reconfigure();
    }
    EDDTableImport.onReferenceRecordsLoad = onReferenceRecordsLoad;
    // This is called by our instance of selectMajorKindStep to announce changes.
    function selectMajorKindCallback() {
        // This is a bit of a hack.  We want to change the pulldown settings in Step 3 if the mode in Step 1 is changed,
        // but leave the pulldown alone otherwise (including when Step 2 announces its own changes.)
        // TODO: Make Step 3 track this with an internal variable.
        if (EDDTableImport.selectMajorKindStep.interpretationMode == 'mdv') {
            // A default set of pulldown settings for this mode
            EDDTableImport.identifyStructuresStep.pulldownSettings = [TypeEnum.Assay_Line_Names, TypeEnum.Metabolite_Name];
        }
        EDDTableImport.rawInputStep.previousStepChanged();
    }
    EDDTableImport.selectMajorKindCallback = selectMajorKindCallback;
    // This is called by our instance of Step 2, RawInputStep to announce changes.
    // We just pass the signal along to Step 3: IdentifyStructuresStep.
    function rawInputCallback() {
        EDDTableImport.identifyStructuresStep.previousStepChanged();
    }
    EDDTableImport.rawInputCallback = rawInputCallback;
    // This is called by our instance of Step 3, IdentifyStructuresStep to announce changes.
    // We just pass the signal along to Step 4: TypeDisambiguationStep.
    function identifyStructuresCallback() {
        EDDTableImport.typeDisambiguationStep.previousStepChanged();
    }
    EDDTableImport.identifyStructuresCallback = identifyStructuresCallback;
    // This is called by our instance of TypeDisambiguationStep to announce changes.
    // All we do currently is repopulate the debug area.
    function typeDisambiguationCallback() {
        //        var parsedSets = EDDTableImport.identifyStructuresStep.parsedSets;
        var resolvedSets = EDDTableImport.typeDisambiguationStep.createSetsForSubmission();
        // if the debug area is there, set its value to JSON of parsed sets
        //        $('#jsondebugarea').val(JSON.stringify(resolvedSets));
        EDDTableImport.reviewStep.previousStepChanged();
    }
    EDDTableImport.typeDisambiguationCallback = typeDisambiguationCallback;
    // tells step 3 that step 2 has just begun processing file input
    function processingFileCallback() {
        EDDTableImport.identifyStructuresStep.processingFileInPreviousStep();
    }
    EDDTableImport.processingFileCallback = processingFileCallback;
    function reviewStepCallback() {
        // nothing to do! no subsequent steps
    }
    EDDTableImport.reviewStepCallback = reviewStepCallback;
    // When the submit button is pushed, fetch the most recent record sets from our IdentifyStructuresStep instance,
    // and embed them in the hidden form field that will be submitted to the server.
    // Note that this is not all that the server needs, in order to successfully process an import.
    // It also reads other form elements from the page, created by SelectMajorKindStep and TypeDisambiguationStep.
    function submitForImport() {
        var json;
        var resolvedSets = EDDTableImport.typeDisambiguationStep.createSetsForSubmission();
        json = JSON.stringify(resolvedSets);
        $('#jsonoutput').val(json);
        $('#jsondebugarea').val(json);
    }
    EDDTableImport.submitForImport = submitForImport;
    // The usual click-to-disclose callback.  Perhaps this should be in Utl.ts?
    function disclose() {
        $(this).closest('.disclose').toggleClass('discloseHide');
        return false;
    }
    EDDTableImport.disclose = disclose;
    var DEFAULT_MASTER_PROTOCOL = 'unspecified_protocol';
    // The class responsible for everything in the "Step 1" box that you see on the data import page.
    // Here we provide UI for selecting the major kind of import, and the Protocol that the data should be stored under.
    // These choices affect the behavior of all subsequent steps.
    var SelectMajorKindStep = (function () {
        function SelectMajorKindStep(nextStepCallback) {
            this.multiProtocolModes = ['biolector', 'mdv', 'hplc', 'tr']; //TODO: theseneed verification
            this.masterProtocol = 0;
            this.interpretationMode = null; // We rely on a separate call to reconfigure() to set this properly.
            this.inputRefreshTimerID = null;
            this.nextStepCallback = nextStepCallback;
            var reProcessOnChange;
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
            reProcessOnChange = ['#stdlayout', '#trlayout', '#hplclayout', '#prlayout', '#mdvlayout', '#biolectorlayout'];
            $(reProcessOnChange.join(',')).on('click', this.reconfigure.bind(this)); // TODO:
            // change back to queueReconfigure() for optimization!
        }
        // Start a timer to wait before calling the reconfigure routine.
        // This way we condense multiple possible events from the radio buttons and/or pulldown into one.
        SelectMajorKindStep.prototype.queueReconfigure = function () {
            if (this.inputRefreshTimerID) {
                clearTimeout(this.inputRefreshTimerID);
            }
            this.inputRefreshTimerID = setTimeout(this.reconfigure.bind(this), 250);
        };
        // Read the settings out of the UI and pass along.
        // If the interpretation mode has changed, all the subsequent steps will need a refresh.
        // If the master Protocol pulldown has changed, Step 4 will need a refresh,
        // specifically the master Assay pulldown and Assay/Line disambiguation section.
        SelectMajorKindStep.prototype.reconfigure = function () {
            // Don't inline these into the if statement or the second one might not be called!
            var a = this.checkInterpretationMode();
            var b = this.checkMasterProtocol();
            if (a || b) {
                this.nextStepCallback();
            }
        };
        // If the interpretation mode value has changed, note the change and return 'true'.
        // Otherwise return 'false'.
        SelectMajorKindStep.prototype.checkInterpretationMode = function () {
            // Find every input element of type 'radio' with the name attribute of 'datalayout' that's checked.
            // Should return 0 or 1 elements.
            var modeRadio = $("input[type='radio'][name='datalayout']:checked");
            // If none of them are checked, we don't have enough information to handle any next steps.
            if (modeRadio.length < 1) {
                return false;
            }
            var radioValue = modeRadio.val();
            if (this.interpretationMode == radioValue) {
                return false;
            }
            this.interpretationMode = radioValue;
            return true;
        };
        // If the master Protocol pulldown value has changed, note the change and return 'true'.
        // Otherwise return 'false'.
        SelectMajorKindStep.prototype.checkMasterProtocol = function () {
            var protocolInput = $('#masterProtocol');
            var p = parseInt(protocolInput.val(), 10);
            if (this.masterProtocol === p) {
                return false;
            }
            this.masterProtocol = p;
            return true;
        };
        SelectMajorKindStep.prototype.getUserWarnings = function () {
            return [];
        };
        SelectMajorKindStep.prototype.getUserErrors = function () {
            return [];
        };
        SelectMajorKindStep.prototype.requiredInputsProvided = function () {
            var masterProtocol = $('#masterProtocol').val();
            return (this.multiProtocolModes.indexOf(this.interpretationMode) >= 0) ||
                (masterProtocol != DEFAULT_MASTER_PROTOCOL);
        };
        SelectMajorKindStep.prototype.previousStepChanged = function () {
            // no-op. no previous steps!
        };
        return SelectMajorKindStep;
    })();
    EDDTableImport.SelectMajorKindStep = SelectMajorKindStep;
    // The class responsible for everything in the "Step 2" box that you see on the data import page.
    // It needs to parse the raw data from typing or pasting in the input box, or a dragged-in file,
    // into a null-padded rectangular grid that can be easily used by the next step.
    // Depending on the kind of import chosen in Step 1, this step will accept different kinds of files,
    // and handle the file drag in different ways.
    // For example, when the import kind is "Standard" and the user drags in a CSV file, the file is parsed
    // in-browser and the contents are placed in the text box.  When the import kind is "biolector" and the user
    // drags in an XML file, the file is sent to the server and parsed there, and the resulting data is passed
    // back to the browser and placed in the text box.
    var RawInputStep = (function () {
        function RawInputStep(selectMajorKindStep, nextStepCallback, processingFileCallBack) {
            this.haveInputData = false;
            this.processingFile = false; //true while the input is being processed (locally or remotely)
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
            this.processingFileCallback = processingFileCallback;
            this.nextStepCallback = nextStepCallback;
        }
        // In practice, the only time this will be called is when Step 1 changes,
        // which may call for a reconfiguration of the controls in this step.
        RawInputStep.prototype.previousStepChanged = function () {
            var mode = this.selectMajorKindStep.interpretationMode;
            // update input visibility based on user selection in step 1
            this.updateInputVisible();
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
            if (mode === 'hplc') {
                // HPLC data is expected as a text file.
                this.nextStepCallback();
                return;
            }
            if (mode === 'mdv') {
                // When JBEI MDV format documents are pasted in, it's always from Excel, so they're always tab-separated.
                this.setSeparatorType('tab');
                // We also never ignore gaps, or transpose, for MDV documents.
                this.setIgnoreGaps(false);
                this.setTranspose(false);
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
        };
        RawInputStep.prototype.queueReprocessRawData = function () {
            // Start a timer to wait before calling the routine that remakes the graph.
            // This way we're not bothering the user with the long redraw process when
            // they are making fast edits.
            if (this.haveInputData) {
                processingFileCallback();
            }
            if (this.inputRefreshTimerID) {
                clearTimeout(this.inputRefreshTimerID);
            }
            this.inputRefreshTimerID = setTimeout(this.reprocessRawData.bind(this), 3000);
        };
        // processes raw user input entered directly into the text area
        RawInputStep.prototype.reprocessRawData = function () {
            var _this = this;
            var mode, delimiter, input;
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
            }
            else {
                // All other formats (so far) are interpreted from a grid.
                // Even biolector XML - which is converted to standard records on the server, then passed back.
                // Note that biolector and hplc are left out here - we don't want to do any "inferring" with them.
                if (mode === 'std' || mode === 'tr' || mode === 'pr') {
                    // If the user hasn't deliberately chosen a setting for 'transpose', we will do
                    // some analysis to attempt to guess which orientation the data needs to have.
                    if (!this.userClickedOnTranspose) {
                        this.inferTransposeSetting(mode, input.input);
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
                    this.gridFromTextField = (input.input[0] || []).map(function (_, i) {
                        return input.input.map(function (row) { return row[i] || ''; });
                    });
                }
                else {
                    this.gridRowMarkers = [];
                    this.gridFromTextField = (input.input || []).map(function (row) {
                        _this.gridRowMarkers.push(row.shift());
                        return row;
                    });
                }
                // Give labels to any header positions that got 'null' for a value.
                this.gridRowMarkers = this.gridRowMarkers.map(function (value) { return value || '?'; });
            }
            this.processingFile = false;
            this.nextStepCallback();
        };
        // Here, we take a look at the type of the dropped file and decide whether to
        // send it to the server, or process it locally.
        // We inform the FileDropZone of our decision by setting flags in the fileContiner object,
        // which will be inspected when this function returns.
        RawInputStep.prototype.fileDropped = function (fileContainer) {
            this.haveInputData = true;
            processingFileCallback();
            var mode = this.selectMajorKindStep.interpretationMode;
            fileContainer.extraHeaders['Import-Mode'] = mode;
            var ft = fileContainer.fileType;
            // We'll process csv files locally.
            if ((ft === 'csv' || ft === 'plaintext') &&
                (mode === 'std' || mode === 'tr' || mode === 'pr')) {
                $('#processingFileLocallyLabel').removeClass('off');
                $('#step2textarea').attr("disabled", "disabled");
                fileContainer.skipProcessRaw = false;
                fileContainer.skipUpload = true;
                return;
            }
            // With Excel documents, we need some server-side tools.
            // We'll signal the dropzone to upload this, and receive processed results.
            if ((ft === 'excel') &&
                (mode === 'std' || mode === 'tr' || mode === 'pr' || mode === 'mdv')) {
                this.showFileDropped(fileContainer);
                fileContainer.skipProcessRaw = true;
                fileContainer.skipUpload = false;
                return;
            }
            if ((ft === 'csv' || ft === 'plaintext') &&
                (mode === 'hplc')) {
                this.showFileDropped(fileContainer);
                fileContainer.skipProcessRaw = true;
                fileContainer.skipUpload = false;
                return;
            }
            if (ft === 'xml' && mode === 'biolector') {
                this.showFileDropped(fileContainer);
                fileContainer.skipProcessRaw = true;
                fileContainer.skipUpload = false;
                return;
            }
            // By default, skip any further processing
            fileContainer.skipProcessRaw = true;
            fileContainer.skipUpload = true;
        };
        // This function is passed the usual fileContainer object, but also a reference to the
        // full content of the dropped file.  So, for example, in the case of parsing a csv file,
        // we just drop that content into the text box and we're done.
        RawInputStep.prototype.fileRead = function (fileContainer, result) {
            this.haveInputData = true;
            processingFileCallback();
            if (fileContainer.fileType === 'csv') {
                // Since we're handling this format entirely client-side, we can get rid of the
                // drop zone immediately.
                fileContainer.skipUpload = true;
                this.clearDropZone();
                $("#step2textarea").val(result);
                this.inferSeparatorType();
                this.reprocessRawData();
                return;
            }
        };
        // This is called upon receiving a response from a file upload operation,
        // and unlike fileRead() above, is passed a processed result from the server as a second argument,
        // rather than the raw contents of the file.
        RawInputStep.prototype.fileReturnedFromServer = function (fileContainer, result) {
            var mode = this.selectMajorKindStep.interpretationMode;
            // Whether we clear the file info area entirely, or just update its status,
            // we know we no longer need the 'sending' status.
            $('#fileDropInfoSending').addClass('off');
            if (mode === 'biolector' || mode === 'hplc') {
                var d = result.file_data;
                var t = 0;
                d.forEach(function (set) { t += set.data.length; });
                $('<p>').text('Found ' + d.length + ' measurements with ' + t + ' total data points.').appendTo($("#fileDropInfoLog"));
                this.processedSetsFromFile = d;
                this.processedSetsAvailable = true;
                this.processingFile = false;
                // Call this directly, skipping over reprocessRawData() since we don't need it.
                this.nextStepCallback();
                return;
            }
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
        };
        RawInputStep.prototype.parseRawInput = function (delimiter, mode) {
            var rawText, longestRow, rows, multiColumn;
            rawText = $('#step2textarea').val();
            rows = [];
            // find the highest number of columns in a row
            longestRow = rawText.split(/[ \r]*\n/).reduce(function (prev, rawRow) {
                var row;
                if (rawRow !== '') {
                    row = rawRow.split(delimiter);
                    rows.push(row);
                    return Math.max(prev, row.length);
                }
                return prev;
            }, 0);
            this.haveInputData = rows.length > 0;
            // pad out rows so it is rectangular
            if (mode === 'std' || mode === 'tr' || mode === 'pr') {
                rows.forEach(function (row) {
                    while (row.length < longestRow) {
                        row.push('');
                    }
                });
            }
            // restore normal editing state in case disabled by file drop / local file processing
            // (dropzone follows a different path and has different wait indicators)
            $('#processingFileLocallyLabel').addClass('off');
            $('#step2textarea').removeAttr("disabled");
            return {
                'input': rows,
                'columns': longestRow
            };
        };
        RawInputStep.prototype.updateInputVisible = function () {
            var missingStep1Inputs = !this.selectMajorKindStep.requiredInputsProvided();
            $('#completeStep1Label').toggleClass('off', !missingStep1Inputs);
            $('#step2textarea').toggleClass('off', missingStep1Inputs);
        };
        // Reset and hide the info box that appears when a file is dropped,
        // and reveal the text entry area
        // This also clears the "processedSetsAvailable" flag because it assumes that
        // the text entry area is now the preferred data source for subsequent steps.
        RawInputStep.prototype.clearDropZone = function () {
            this.updateInputVisible();
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
        };
        // Reset and show the info box that appears when a file is dropped,
        // and reveal the text entry area.
        RawInputStep.prototype.showFileDropped = function (fileContainer) {
            // Set the icon image properly
            $('#fileDropInfoIcon').removeClass('xml');
            $('#fileDropInfoIcon').removeClass('excel');
            if (fileContainer.fileType === 'xml') {
                $('#fileDropInfoIcon').addClass('xml');
            }
            else if (fileContainer.fileType === 'excel') {
                $('#fileDropInfoIcon').addClass('excel');
            }
            $('#step2textarea').addClass('off');
            $('#fileDropInfoArea').removeClass('off');
            $('#fileDropInfoSending').removeClass('off');
            $('#fileDropInfoName').text(fileContainer.file.name);
            $('#fileUploadMessage').text('Sending ' + Utl.JS.sizeToString(fileContainer.file.size) + ' To Server...');
            //            $('#fileDropInfoLog').empty();
            this.activeDraggedFile = fileContainer;
        };
        RawInputStep.prototype.reset = function () {
            this.haveInputData = false;
            this.clearDropZone();
            $('#step2textarea').val('');
            this.reprocessRawData();
        };
        RawInputStep.prototype.inferTransposeSetting = function (mode, rows) {
            // as a user convenience, support the only known use-case for proteomics -- taking
            // "short and fat" output from the skyline import tool as input. TODO: reconsider
            // this when integrating the Skyline tool into the import page (EDD-240).
            if (mode === 'pr') {
                this.setTranspose(true);
                return;
            }
            // The most straightforward method is to take the top row, and the first column,
            // and analyze both to see which one most likely contains a run of timestamps.
            // We'll also do the same for the second row and the second column, in case the
            // timestamps are underneath some other header.
            var arraysToAnalyze, arraysScores, setTranspose;
            // Note that with empty or too-small source data, these arrays will either remain
            // empty, or become 'null'
            arraysToAnalyze = [
                rows[0] || [],
                rows[1] || [],
                (rows || []).map(function (row) { return row[0]; }),
                (rows || []).map(function (row) { return row[1]; }) // Second column
            ];
            arraysScores = arraysToAnalyze.map(function (row, i) {
                var score = 0, prev, nnPrev;
                if (!row || row.length === 0) {
                    return 0;
                }
                prev = nnPrev = undefined;
                row.forEach(function (value, j, r) {
                    var t;
                    if (value) {
                        t = parseFloat(value.replace(/,/g, ''));
                    }
                    if (!isNaN(t)) {
                        if (!isNaN(prev) && t > prev) {
                            score += 2;
                        }
                        else if (!isNaN(nnPrev) && t > nnPrev) {
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
            }
            else {
                setTranspose = arraysScores[1] > arraysScores[3];
            }
            this.setTranspose(setTranspose);
        };
        RawInputStep.prototype.inferGapsSetting = function () {
            // Count the number of blank values at the end of each column
            // Count the number of blank values in between non-blank data
            // If more than three times as many as at the end, default to ignore gaps
            var intra = 0, extra = 0;
            this.gridFromTextField.forEach(function (row) {
                var notNull = false;
                // copy and reverse to loop from the end
                row.slice(0).reverse().forEach(function (value) {
                    if (!value) {
                        notNull ? ++extra : ++intra;
                    }
                    else {
                        notNull = true;
                    }
                });
            });
            var result = extra > (intra * 3);
            this.setIgnoreGaps(result);
        };
        RawInputStep.prototype.processMdv = function (input) {
            var _this = this;
            var rows, colLabels, compounds, orderedComp;
            colLabels = [];
            rows = input.slice(0); // copy
            // If this word fragment is in the first row, drop the whole row.
            // (Ignoring a Q of unknown capitalization)
            if (rows[0].join('').match(/uantitation/g)) {
                rows.shift();
            }
            compounds = {};
            orderedComp = [];
            rows.forEach(function (row) {
                var first, marked, name, index;
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
                        compounds[name] = { 'originalRows': {}, 'processedAssayCols': {} };
                        orderedComp.push(name);
                    }
                    compounds[name].originalRows[index] = row.slice(0);
                }
            });
            $.each(compounds, function (name, value) {
                var indices;
                // First gather up all the marker indexes given for this compound
                indices = $.map(value.originalRows, function (_, index) { return parseInt(index, 10); });
                indices.sort(function (a, b) { return a - b; }); // sort ascending
                // Run through the set of columnLabels above, assembling a marking number for each,
                // by drawing - in order - from this collected row data.
                colLabels.forEach(function (label, index) {
                    var parts, anyFloat;
                    parts = [];
                    anyFloat = false;
                    indices.forEach(function (ri) {
                        var original, cell;
                        original = value.originalRows[ri];
                        cell = original[index];
                        if (cell) {
                            cell = cell.replace(/,/g, '');
                            if (isNaN(parseFloat(cell))) {
                                if (anyFloat) {
                                    parts.push('');
                                }
                            }
                            else {
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
            Array.prototype.push.apply(this.gridFromTextField, orderedComp.map(function (name) {
                var compound, row, colLookup;
                _this.gridRowMarkers.push(name);
                compound = compounds[name];
                row = [];
                colLookup = compound.processedAssayCols;
                // generate row cells by mapping column labels to processed columns
                Array.prototype.push.apply(row, colLabels.map(function (_, index) { return colLookup[index] || ''; }));
                return row;
            }));
        };
        // This gets called when there is a paste event.
        RawInputStep.prototype.pastedRawData = function () {
            // We do this using a timeout so the rest of the paste events fire, and get the pasted result.
            this.haveInputData = true;
            window.setTimeout(this.inferSeparatorType.bind(this), 1);
        };
        RawInputStep.prototype.inferSeparatorType = function () {
            if (this.selectMajorKindStep.interpretationMode !== "mdv") {
                var text = $('#step2textarea').val() || '', test;
                test = text.split('\t').length >= text.split(',').length;
                this.setSeparatorType(test ? 'tab' : 'csv');
            }
        };
        RawInputStep.prototype.setIgnoreGaps = function (value) {
            var ignoreGaps = $('#ignoreGaps');
            if (value === undefined) {
                value = ignoreGaps.prop('checked');
            }
            else {
                ignoreGaps.prop('checked', value);
            }
            this.ignoreDataGaps = value;
        };
        RawInputStep.prototype.setTranspose = function (value) {
            var transpose = $('#transpose');
            if (value === undefined) {
                value = transpose.prop('checked');
            }
            else {
                transpose.prop('checked', value);
            }
            this.transpose = value;
        };
        RawInputStep.prototype.setSeparatorType = function (value) {
            var separatorPulldown = $('#rawdataformatp');
            if (value === undefined) {
                value = separatorPulldown.val();
            }
            else {
                separatorPulldown.val(value);
            }
            this.separatorType = value;
        };
        RawInputStep.prototype.clickedOnIgnoreDataGaps = function () {
            this.userClickedOnIgnoreDataGaps = true;
            this.reprocessRawData(); // This will take care of reading the status of the checkbox
        };
        RawInputStep.prototype.clickedOnTranspose = function () {
            this.userClickedOnTranspose = true;
            this.reprocessRawData();
        };
        // This handles insertion of a tab into the textarea.
        // May be glitchy.
        RawInputStep.prototype.suppressNormalTab = function (e) {
            var input, text;
            this.haveInputData = true;
            if (e.which === 9) {
                input = e.target;
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
        };
        RawInputStep.prototype.getGrid = function () {
            return this.gridFromTextField;
        };
        RawInputStep.prototype.getUserWarnings = function () {
            return [];
        };
        RawInputStep.prototype.getUserErrors = function () {
            return [];
        };
        RawInputStep.prototype.requiredInputsProvided = function () {
            return this.selectMajorKindStep.requiredInputsProvided() && this.haveInputData;
        };
        return RawInputStep;
    })();
    EDDTableImport.RawInputStep = RawInputStep;
    // Magic numbers used in pulldowns to assign types to rows/fields.
    var TypeEnum = (function () {
        function TypeEnum() {
        }
        TypeEnum.Gene_Names = 10;
        TypeEnum.RPKM_Values = 11;
        TypeEnum.Assay_Line_Names = 1;
        TypeEnum.Protein_Name = 12;
        TypeEnum.Metabolite_Names = 2;
        TypeEnum.Timestamp = 3;
        TypeEnum.Metadata_Name = 4;
        TypeEnum.Metabolite_Name = 5;
        return TypeEnum;
    })();
    EDDTableImport.TypeEnum = TypeEnum;
    // The class responsible for everything in the "Step 3" box that you see on the data import page.
    // Get the grid from the previous step, and draw it as a table with puldowns for specifying the content
    // of the rows and columns, as well as checkboxes to enable or disable rows or columns.
    // Interpret the current grid and the settings on the current table into EDD-friendly sets.
    var IdentifyStructuresStep = (function () {
        function IdentifyStructuresStep(selectMajorKindStep, rawInputStep, nextStepCallback) {
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
            this.warningMessages = [];
            this.errorMessages = [];
            $('#dataTableDiv')
                .on('mouseover mouseout', 'td', this.highlighterF.bind(this))
                .on('dblclick', 'td', this.singleValueDisablerF.bind(this));
            $('#resetstep3').on('click', this.resetEnabledFlagMarkers.bind(this));
            this.DEFAULT_STEP3_PULLDOWN_VALUE = 0;
        }
        // called to inform this step that the immediately preceding step has begun processing
        // its inputs. The assumption is that the processing is taking place until the next call to
        // previousStepChanged().
        IdentifyStructuresStep.prototype.processingFileInPreviousStep = function () {
            $('#processingStep2ResultsLabel').removeClass('off');
            $('#enterDataInStep2').addClass('off');
            $('#dataTableDiv').find("input,button,textarea,select").attr("disabled", "disabled");
        };
        IdentifyStructuresStep.prototype.previousStepChanged = function () {
            var _this = this;
            var prevStepComplete = this.rawInputStep.requiredInputsProvided();
            $('#processingStep2ResultsLabel').toggleClass('off', !prevStepComplete);
            $('#enterDataInStep2').toggleClass('off', prevStepComplete);
            $('#dataTableDiv').toggleClass('off', !prevStepComplete);
            var mode = this.selectMajorKindStep.interpretationMode;
            var graph = $('#graphDiv');
            if (mode === 'std' || mode === 'biolector' || mode === 'hplc') {
                this.graphEnabled = true;
            }
            else {
                this.graphEnabled = false;
            }
            var hideGraph = (!this.graphEnabled) || (!prevStepComplete);
            graph.toggleClass('off', hideGraph);
            var gridRowMarkers = this.rawInputStep.gridRowMarkers;
            var grid = this.rawInputStep.getGrid();
            var ignoreDataGaps = this.rawInputStep.ignoreDataGaps;
            if (mode === 'std' || mode === 'tr' || mode === 'pr') {
                gridRowMarkers.forEach(function (value, i) {
                    var type;
                    if (!_this.pulldownUserChangedFlags[i]) {
                        type = _this.figureOutThisRowsDataType(mode, value, grid[i] || []);
                        _this.pulldownSettings[i] = type;
                    }
                });
            }
            // Empty the data table whether we remake it or not...
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
            $('#processingStep2ResultsLabel').addClass('off');
            this.nextStepCallback();
        };
        IdentifyStructuresStep.prototype.figureOutThisRowsDataType = function (mode, label, row) {
            var blank, strings, condensed;
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
            condensed = row.filter(function (v) { return !!v; });
            blank = row.length - condensed.length;
            condensed.forEach(function (v) {
                v = v.replace(/,/g, '');
                if (isNaN(parseFloat(v))) {
                    ++strings;
                }
            });
            // If the label parses into a number and the data contains no strings, call it a
            // timestamp for data
            if (!isNaN(parseFloat(label)) && (strings === 0)) {
                return TypeEnum.Timestamp;
            }
            // No choice by default
            return 0;
        };
        IdentifyStructuresStep.prototype.inferActiveFlags = function (grid) {
            var _this = this;
            // An important thing to note here is that this data is in [y][x] format -
            // that is, it goes by row, then by column, when referencing.
            // This matches Grid.data and Table.dataCells.
            var x, y;
            (grid[0] || []).forEach(function (_, x) {
                if (_this.activeColFlags[x] === undefined) {
                    _this.activeColFlags[x] = true;
                }
            });
            grid.forEach(function (row, y) {
                if (_this.activeRowFlags[y] === undefined) {
                    _this.activeRowFlags[y] = true;
                }
                _this.activeFlags[y] = _this.activeFlags[y] || [];
                row.forEach(function (_, x) {
                    if (_this.activeFlags[y][x] === undefined) {
                        _this.activeFlags[y][x] = true;
                    }
                });
            });
        };
        IdentifyStructuresStep.prototype.constructDataTable = function (mode, grid, gridRowMarkers) {
            var _this = this;
            var controlCols, pulldownOptions, table, colgroup, body, row;
            var startTime = new Date();
            console.log("Start of IdentifyStructuresStep.constructDataTable()");
            this.dataCells = [];
            this.colCheckboxCells = [];
            this.colObjects = [];
            this.rowLabelCells = [];
            this.rowCheckboxCells = [];
            controlCols = ['checkbox', 'pulldown', 'label'];
            if (mode === 'tr') {
                pulldownOptions = [
                    ['--', this.DEFAULT_STEP3_PULLDOWN_VALUE],
                    ['Entire Row Is...', [
                            ['Gene Names', TypeEnum.Gene_Names],
                            ['RPKM Values', TypeEnum.RPKM_Values]
                        ]
                    ]
                ];
            }
            else if (mode === 'pr') {
                pulldownOptions = [
                    ['--', this.DEFAULT_STEP3_PULLDOWN_VALUE],
                    ['Entire Row Is...', [
                            ['Assay/Line Names', TypeEnum.Assay_Line_Names],
                        ]
                    ],
                    ['First Column Is...', [
                            ['Protein Name', TypeEnum.Protein_Name]
                        ]
                    ]
                ];
            }
            else {
                pulldownOptions = [
                    ['--', this.DEFAULT_STEP3_PULLDOWN_VALUE],
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
            table = $('<table>').attr('cellspacing', '0').appendTo($('#dataTableDiv'))
                .on('click', '[name=enableColumn]', function (ev) {
                t.toggleTableColumn(ev.target);
            }).on('click', '[name=enableRow]', function (ev) {
                t.toggleTableRow(ev.target);
            }).on('change', '.pulldownCell > select', function (ev) {
                var targ = $(ev.target);
                t.changedRowDataTypePulldown(parseInt(targ.attr('i'), 10), parseInt(targ.val(), 10));
            })[0];
            // One of the objects here will be a column group, with col objects in it.
            // This is an interesting twist on DOM behavior that you should probably google.
            colgroup = $('<colgroup>').appendTo(table);
            controlCols.forEach(function () {
                $('<col>').appendTo(colgroup);
            });
            body = $('<tbody>').appendTo(table)[0];
            // Start with three columns, for the checkboxes, pulldowns, and labels.
            // (These will not be tracked in Table.colObjects.)
            // add col elements for each data column
            var nColumns = 0;
            (grid[0] || []).forEach(function () {
                _this.colObjects.push($('<col>').appendTo(colgroup)[0]);
                nColumns++;
            });
            ///////////////////////////////////////////////////////////////////////////////////////
            // First row: spacer cells, followed by checkbox cells for each data column
            ///////////////////////////////////////////////////////////////////////////////////
            row = body.insertRow();
            // spacer cells have x and y set to 0 to remove from highlight grid
            controlCols.forEach(function () {
                $(row.insertCell()).attr({ 'x': '0', 'y': 0 });
            });
            (grid[0] || []).forEach(function (_, i) {
                var cell, box;
                cell = $(row.insertCell()).attr({ 'id': 'colCBCell' + i, 'x': 1 + i, 'y': 0 })
                    .addClass('checkBoxCell');
                box = $('<input type="checkbox"/>').appendTo(cell)
                    .val(i.toString())
                    .attr({ 'id': 'enableColumn' + i, 'name': 'enableColumn' })
                    .prop('checked', _this.activeColFlags[i]);
                _this.colCheckboxCells.push(cell[0]);
            });
            this.pulldownObjects = []; // We don't want any lingering old objects in this
            ///////////////////////////////////////////////////////////////////////////////////////
            // The rest of the rows: A pulldown, a checkbox, a row label, and a row of data.
            //////////////////////////////////////////////////////////////////////////////////////
            grid.forEach(function (values, i) {
                var cell;
                row = body.insertRow();
                // checkbox cell
                cell = $(row.insertCell()).addClass('checkBoxCell')
                    .attr({ 'id': 'rowCBCell' + i, 'x': 0, 'y': i + 1 });
                $('<input type="checkbox"/>')
                    .attr({ 'id': 'enableRow' + i, 'name': 'enableRow', })
                    .val(i.toString())
                    .prop('checked', _this.activeRowFlags[i])
                    .appendTo(cell);
                _this.rowCheckboxCells.push(cell[0]);
                ////////////////////
                // pulldown cell
                ///////////////////
                cell = $(row.insertCell()).addClass('pulldownCell')
                    .attr({ 'id': 'rowPCell' + i, 'x': 0, 'y': i + 1 });
                // use existing setting, or use the last if rows.length > settings.length, or blank
                _this.pulldownSettings[i] = _this.pulldownSettings[i]
                    || _this.pulldownSettings.slice(-1)[0] || 0;
                _this.populatePulldown(cell = $('<select>')
                    .attr({ 'id': 'row' + i + 'type', 'name': 'row' + i + 'type', 'i': i })
                    .appendTo(cell), pulldownOptions, _this.pulldownSettings[i]);
                _this.pulldownObjects.push(cell[0]);
                /////////////////////
                // label cell
                ////////////////////
                cell = $(row.insertCell()).attr({ 'id': 'rowMCell' + i, 'x': 0, 'y': i + 1 });
                $('<div>').text(gridRowMarkers[i]).appendTo(cell);
                _this.rowLabelCells.push(cell[0]);
                /////////////////////////
                // the table data itself
                /////////////////////////
                _this.dataCells[i] = [];
                values.forEach(function (value, x) {
                    var short;
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
                    _this.dataCells[i].push(cell[0]);
                });
            });
            this.applyTableDataTypeStyling(grid);
            var endTime = new Date();
            var elapsedSeconds = (endTime.getTime() - startTime.getTime()) / 1000;
            console.log("End of IdentifyStructuresStep.constructDataTable(). Table: ", grid.length, " rows X ", nColumns, " columns. Elapsed time: ", elapsedSeconds, " s");
        };
        // A recursive function to populate a pulldown with optional optiongroups,
        // and a default selection
        IdentifyStructuresStep.prototype.populatePulldown = function (select, options, value) {
            var _this = this;
            options.forEach(function (option) {
                if (typeof option[1] === 'number') {
                    $('<option>').text(option[0]).val(option[1])
                        .prop('selected', option[1] === value)
                        .appendTo(select);
                }
                else {
                    _this.populatePulldown($('<optgroup>').attr('label', option[0]).appendTo(select), option[1], value);
                }
            });
        };
        // This routine does a bit of additional styling to the Step 3 data table.
        // It removes and re-adds the dataTypeCell css classes according to the pulldown settings for each row.
        IdentifyStructuresStep.prototype.applyTableDataTypeStyling = function (grid) {
            var _this = this;
            grid.forEach(function (row, index) {
                var pulldown, hlLabel, hlRow;
                pulldown = _this.pulldownSettings[index] || 0;
                hlLabel = hlRow = false;
                if (pulldown === TypeEnum.Assay_Line_Names || pulldown === TypeEnum.Metabolite_Names) {
                    hlRow = true;
                }
                else if (pulldown === TypeEnum.Timestamp ||
                    pulldown === TypeEnum.Metadata_Name ||
                    pulldown === TypeEnum.Metabolite_Name) {
                    hlLabel = true;
                }
                $(_this.rowLabelCells[index]).toggleClass('dataTypeCell', hlLabel);
                row.forEach(function (_, col) {
                    $(_this.dataCells[index][col]).toggleClass('dataTypeCell', hlRow);
                });
            });
        };
        IdentifyStructuresStep.prototype.redrawIgnoredValueMarkers = function (ignoreDataGaps) {
            this.dataCells.forEach(function (row) {
                row.forEach(function (cell) {
                    var toggle = !ignoreDataGaps && !!cell.getAttribute('isblank');
                    $(cell).toggleClass('ignoredLine', toggle);
                });
            });
        };
        IdentifyStructuresStep.prototype.redrawEnabledFlagMarkers = function () {
            var _this = this;
            this.dataCells.forEach(function (row, y) {
                var toggle = !_this.activeRowFlags[y];
                $(_this.rowLabelCells[y]).toggleClass('disabledLine', toggle);
                row.forEach(function (cell, x) {
                    toggle = !_this.activeFlags[y][x]
                        || !_this.activeColFlags[x]
                        || !_this.activeRowFlags[y];
                    $(cell).toggleClass('disabledLine', toggle);
                });
            });
            this.colCheckboxCells.forEach(function (box, x) {
                var toggle = !_this.activeColFlags[x];
                $(box).toggleClass('disabledLine', toggle);
            });
        };
        IdentifyStructuresStep.prototype.changedRowDataTypePulldown = function (index, value) {
            var _this = this;
            var selected;
            var grid = this.rawInputStep.getGrid();
            // The value does not necessarily match the selectedIndex.
            selected = this.pulldownObjects[index].selectedIndex;
            this.pulldownSettings[index] = value;
            this.pulldownUserChangedFlags[index] = true;
            if (value === TypeEnum.Timestamp ||
                value === TypeEnum.Metadata_Name ||
                value === TypeEnum.Metabolite_Name ||
                value === TypeEnum.Protein_Name) {
                // "Timestamp", "Metadata", or other single-table-cell types
                // Set all the rest of the pulldowns to this,
                // based on the assumption that the first is followed by many others
                this.pulldownObjects.slice(index + 1).every(function (pulldown) {
                    var select, i;
                    select = $(pulldown);
                    i = parseInt(select.attr('i'), 10);
                    if (_this.pulldownUserChangedFlags[i]
                        && _this.pulldownSettings[i] !== 0) {
                        return false; // false for break
                    }
                    select.val(value.toString());
                    _this.pulldownSettings[i] = value;
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
                if (value === TypeEnum.Metabolite_Name || value === TypeEnum.Timestamp || value === TypeEnum.Metadata_Name) {
                    grid.forEach(function (_, i) {
                        var c = _this.pulldownSettings[i];
                        if (value === TypeEnum.Metabolite_Name) {
                            if (c === TypeEnum.Timestamp || c === TypeEnum.Metadata_Name) {
                                _this.pulldownObjects[i].selectedIndex = 0;
                                _this.pulldownSettings[i] = 0;
                            }
                            else if (c === TypeEnum.Metabolite_Names) {
                                _this.pulldownObjects[i].selectedIndex = TypeEnum.Assay_Line_Names;
                                _this.pulldownSettings[i] = TypeEnum.Assay_Line_Names;
                            }
                        }
                        else if ((value === TypeEnum.Timestamp || value === TypeEnum.Metadata_Name) && c === TypeEnum.Metabolite_Name) {
                            _this.pulldownObjects[i].selectedIndex = 0;
                            _this.pulldownSettings[i] = 0;
                        }
                    });
                }
            }
            this.queueInterpretRowTypePullDowns();
        };
        // Start a timer to wait before calling interpretRowDataTypePulldowns().
        // This way we condense multiple events from pulldown auto-selection into a single event
        IdentifyStructuresStep.prototype.queueInterpretRowTypePullDowns = function () {
            if (this.interpretRowTypePullDownTImerID) {
                clearTimeout(this.interpretRowTypePullDownTImerID);
            }
            this.interpretRowTypePullDownTImerID = setTimeout(this.interpretRowDataTypePulldowns.bind(this), 30);
        };
        // update state as a result of row datatype pulldown selection
        IdentifyStructuresStep.prototype.interpretRowDataTypePulldowns = function () {
            console.log('Starting interpretRowDataTypePullDowns()');
            var start = new Date();
            var grid = this.rawInputStep.getGrid();
            this.applyTableDataTypeStyling(grid);
            this.interpretDataTable();
            this.queueGraphRemake();
            var ellapsedSeconds = (new Date().getTime() - start.getTime()) / 1000;
            console.log("End interpretRowDataTypePullDowns(). Elapsed time", ellapsedSeconds, " s. Calling next step.");
            this.nextStepCallback();
        };
        IdentifyStructuresStep.prototype.toggleTableRow = function (box) {
            var value, input, pulldown;
            input = $(box);
            pulldown = input.next();
            value = parseInt(input.val(), 10);
            var active = input.prop('checked');
            this.activeRowFlags[value] = active;
            if (active) {
                pulldown.removeAttr('disabled');
            }
            else {
                pulldown.attr('disabled', 'disabled');
            }
            this.interpretDataTable();
            this.redrawEnabledFlagMarkers();
            // Resetting a disabled row may change the number of rows listed in the Info table.
            this.queueGraphRemake();
            this.nextStepCallback();
        };
        IdentifyStructuresStep.prototype.toggleTableColumn = function (box) {
            var value, input;
            input = $(box);
            value = parseInt(input.val(), 10);
            this.activeColFlags[value] = input.prop('checked');
            this.interpretDataTable();
            this.redrawEnabledFlagMarkers();
            // Resetting a disabled column may change the rows listed in the Info table.
            this.queueGraphRemake();
            this.nextStepCallback();
        };
        IdentifyStructuresStep.prototype.resetEnabledFlagMarkers = function () {
            var _this = this;
            var grid = this.rawInputStep.getGrid();
            grid.forEach(function (row, y) {
                _this.activeFlags[y] = _this.activeFlags[y] || [];
                row.forEach(function (_, x) {
                    _this.activeFlags[y][x] = true;
                });
                _this.activeRowFlags[y] = true;
            });
            (grid[0] || []).forEach(function (_, x) {
                _this.activeColFlags[x] = true;
            });
            // Flip all the checkboxes on in the header cells for the data columns
            $('#dataTableDiv').find('[name=enableColumn]').prop('checked', true);
            // Same for the checkboxes in the row label cells
            $('#dataTableDiv').find('[name=enableRow]').prop('checked', true);
            this.interpretDataTable();
            this.redrawEnabledFlagMarkers();
            this.queueGraphRemake();
            this.nextStepCallback();
        };
        IdentifyStructuresStep.prototype.interpretDataTable = function () {
            var _this = this;
            // This mode means we make a new "set" for each cell in the table, rather than
            // the standard method of making a new "set" for each column in the table.
            var singleMode;
            var single, nonSingle, earliestName;
            var grid = this.rawInputStep.getGrid();
            var gridRowMarkers = this.rawInputStep.gridRowMarkers;
            var ignoreDataGaps = this.rawInputStep.ignoreDataGaps;
            // We'll be accumulating these for disambiguation.
            var seenLineNames = {};
            var seenAssayNames = {};
            var seenMeasurementNames = {};
            var seenMetadataNames = {};
            var disamRawSets = [];
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
                this.rawInputStep.processedSetsFromFile.forEach(function (rawSet, c) {
                    var set, graphSet, uniqueTimes, times, foundMeta;
                    var ln = rawSet.line_name;
                    var an = rawSet.assay_name;
                    var mn = rawSet.measurement_name;
                    uniqueTimes = [];
                    times = {};
                    foundMeta = false;
                    // The procedure for Assays, Measurements, etc is the same:
                    // If the value is blank, we can't build a valid set, so skip to the next set.
                    // If the value is valid but we haven't seen it before, increment and store a uniqueness index.
                    if (!ln && ln !== 0) {
                        return;
                    }
                    if (!mn && mn !== 0) {
                        return;
                    }
                    if (!an && an !== 0) {
                        // if just the assay name is missing, set it to the line name
                        an = ln;
                    }
                    if (!seenLineNames[ln]) {
                        seenLineNames[ln] = true;
                        _this.uniqueLineNames.push(ln);
                    }
                    if (!seenAssayNames[an]) {
                        seenAssayNames[an] = true;
                        _this.uniqueAssayNames.push(an);
                    }
                    if (!seenMeasurementNames[mn]) {
                        seenMeasurementNames[mn] = true;
                        _this.uniqueMeasurementNames.push(mn);
                    }
                    var reassembledData = [];
                    // Slightly different procedure for metadata, but same idea:
                    Object.keys(rawSet.metadata_by_name).forEach(function (key) {
                        var value = rawSet.metadata_by_name[key];
                        if (!seenMetadataNames[key]) {
                            seenMetadataNames[key] = true;
                            _this.uniqueMetadataNames.push(key);
                        }
                        foundMeta = true;
                    });
                    // Validate the provided set of time/value points
                    rawSet.data.forEach(function (xy) {
                        var time, value;
                        if (!JSNumber.isFinite(xy[0])) {
                            // Sometimes people - or Excel docs - drop commas into large numbers.
                            time = parseFloat((xy[0] || '0').replace(/,/g, ''));
                        }
                        else {
                            time = xy[0];
                        }
                        // If we can't get a usable timestamp, discard this point.
                        if (JSNumber.isNaN(time)) {
                            return;
                        }
                        if (!xy[1] && xy[1] !== 0) {
                            // If we're ignoring gaps, skip any undefined/null values.
                            //if (ignoreDataGaps) { return; }    // Note: Forced always-off for now
                            // A null is our standard placeholder value
                            value = null;
                        }
                        else if (!JSNumber.isFinite(xy[1])) {
                            value = parseFloat((xy[1] || '').replace(/,/g, ''));
                        }
                        else {
                            value = xy[1];
                        }
                        if (!times[time]) {
                            times[time] = value;
                            uniqueTimes.push(time);
                            _this.seenAnyTimestamps = true;
                        }
                    });
                    uniqueTimes.sort(function (a, b) { return a - b; }).forEach(function (time) {
                        reassembledData.push([time, times[time]]);
                    });
                    // Only save if we accumulated some data or metadata
                    if (!uniqueTimes.length && !foundMeta) {
                        return;
                    }
                    set = {
                        // Copy across the fields from the RawImportSet record
                        kind: rawSet.kind,
                        line_name: rawSet.line_name,
                        assay_name: rawSet.assay_name,
                        measurement_name: rawSet.measurement_name,
                        metadata_by_name: rawSet.metadata_by_name,
                        data: reassembledData
                    };
                    _this.parsedSets.push(set);
                    graphSet = {
                        'label': (ln ? ln + ': ' : '') + an + ': ' + mn,
                        'name': mn,
                        'units': 'units',
                        'data': reassembledData
                    };
                    _this.graphSets.push(graphSet);
                });
                return;
            }
            // If we're not using pre-processed records, we need to use the pulldown settings in this step
            // (usually set by the user) to determine what mode we're in.
            single = 0;
            nonSingle = 0;
            earliestName = null;
            // Look for the presence of "single measurement type" rows, and rows of all other single-item types
            grid.forEach(function (_, y) {
                var pulldown;
                if (_this.activeRowFlags[y]) {
                    pulldown = _this.pulldownSettings[y];
                    if (pulldown === TypeEnum.Metabolite_Name || pulldown === TypeEnum.Protein_Name) {
                        single++; // Single Measurement Name or Single Protein Name
                    }
                    else if (pulldown === TypeEnum.Metadata_Name || pulldown === TypeEnum.Timestamp) {
                        nonSingle++;
                    }
                    else if (pulldown === TypeEnum.Assay_Line_Names && earliestName === null) {
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
                this.colObjects.forEach(function (_, c) {
                    var cellValue, set;
                    if (!_this.activeColFlags[c]) {
                        return;
                    }
                    cellValue = grid[earliestName][c] || '';
                    if (!cellValue) {
                        return;
                    }
                    // If haven't seen cellValue before, increment and store uniqueness index
                    if (!seenAssayNames[cellValue]) {
                        seenAssayNames[cellValue] = true;
                        _this.uniqueAssayNames.push(cellValue);
                    }
                    grid.forEach(function (row, r) {
                        var pulldown, label, value, timestamp;
                        if (!_this.activeRowFlags[r] || !_this.activeFlags[r][c]) {
                            return;
                        }
                        pulldown = _this.pulldownSettings[r];
                        label = gridRowMarkers[r] || '';
                        value = row[c] || '';
                        if (!pulldown || !label || !value) {
                            return;
                        }
                        var m_name = null;
                        if (pulldown === TypeEnum.Metabolite_Name) {
                            if (!seenMeasurementNames[label]) {
                                seenMeasurementNames[label] = true;
                                _this.uniqueMeasurementNames.push(label);
                            }
                            m_name = label;
                        }
                        else if (pulldown === TypeEnum.Protein_Name) {
                            m_name = label;
                        }
                        else {
                            // If we aren't on a row that's labeled as either a metabolite value
                            // or a protein value, return without making a set.
                            return;
                        }
                        set = {
                            kind: _this.selectMajorKindStep.interpretationMode,
                            line_name: null,
                            assay_name: cellValue,
                            measurement_name: m_name,
                            metadata_by_name: {},
                            data: [[null, value]]
                        };
                        _this.parsedSets.push(set);
                    });
                });
                return;
            }
            // The standard method: Make a "set" for each column of the table
            this.colObjects.forEach(function (_, c) {
                var set, graphSet, uniqueTimes, times, foundMeta;
                // Skip it if the whole column is deactivated
                if (!_this.activeColFlags[c]) {
                    return;
                }
                var reassembledData = []; // We'll fill this out as we go
                set = {
                    kind: _this.selectMajorKindStep.interpretationMode,
                    line_name: null,
                    assay_name: null,
                    measurement_name: null,
                    metadata_by_name: {},
                    data: reassembledData,
                };
                uniqueTimes = [];
                times = {};
                foundMeta = false;
                grid.forEach(function (row, r) {
                    var pulldown, label, value, timestamp;
                    if (!_this.activeRowFlags[r] || !_this.activeFlags[r][c]) {
                        return;
                    }
                    pulldown = _this.pulldownSettings[r];
                    label = gridRowMarkers[r] || '';
                    value = row[c] || '';
                    if (!pulldown) {
                        return;
                    }
                    else if (pulldown === TypeEnum.RPKM_Values) {
                        value = value.replace(/,/g, '');
                        if (value) {
                            reassembledData = [[null, value]];
                        }
                        return;
                    }
                    else if (pulldown === TypeEnum.Gene_Names) {
                        if (value) {
                            set.measurement_name = value;
                        }
                        return;
                    }
                    else if (pulldown === TypeEnum.Timestamp) {
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
                                _this.seenAnyTimestamps = true;
                            }
                        }
                        return;
                    }
                    else if (label === '' || value === '') {
                        // Now that we've dealt with timestamps, we proceed on to other data types.
                        // All the other data types do not accept a blank value, so we weed them out now.
                        return;
                    }
                    else if (pulldown === TypeEnum.Assay_Line_Names) {
                        // If haven't seen value before, increment and store uniqueness index
                        if (!seenAssayNames[value]) {
                            seenAssayNames[value] = true;
                            _this.uniqueAssayNames.push(value);
                        }
                        set.assay_name = value;
                        return;
                    }
                    else if (pulldown === TypeEnum.Metabolite_Names) {
                        // If haven't seen value before, increment and store uniqueness index
                        if (!seenMeasurementNames[value]) {
                            seenMeasurementNames[value] = true;
                            _this.uniqueMeasurementNames.push(value);
                        }
                        set.measurement_name = value;
                        return;
                    }
                    else if (pulldown === TypeEnum.Metadata_Name) {
                        if (!seenMetadataNames[label]) {
                            seenMetadataNames[label] = true;
                            _this.uniqueMetadataNames.push(label);
                        }
                        set.metadata_by_name[label] = value;
                        foundMeta = true;
                    }
                });
                uniqueTimes.sort(function (a, b) { return a - b; }).forEach(function (time) {
                    reassembledData.push([time, times[time]]);
                });
                // only save if accumulated some data or metadata
                if (!uniqueTimes.length && !foundMeta && !reassembledData[0]) {
                    return;
                }
                _this.parsedSets.push(set);
                graphSet = {
                    'label': 'Column ' + c,
                    'name': 'Column ' + c,
                    'units': 'units',
                    'data': reassembledData
                };
                _this.graphSets.push(graphSet);
            });
        };
        IdentifyStructuresStep.prototype.highlighterF = function (e) {
            var cell, x, y;
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
        };
        IdentifyStructuresStep.prototype.singleValueDisablerF = function (e) {
            var cell, x, y;
            // Walk up the item tree until we arrive at a table cell,
            // so we can get the index of the table cell in the table.
            cell = $(e.target).closest('td');
            if (!cell.length) {
                return;
            }
            x = parseInt(cell.attr('x'), 10);
            y = parseInt(cell.attr('y'), 10);
            if (!x || !y || x < 1 || y < 1) {
                return;
            }
            --x;
            --y;
            if (this.activeFlags[y][x]) {
                this.activeFlags[y][x] = false;
            }
            else {
                this.activeFlags[y][x] = true;
            }
            this.interpretDataTable();
            this.redrawEnabledFlagMarkers();
            this.queueGraphRemake();
            this.nextStepCallback();
        };
        IdentifyStructuresStep.prototype.queueGraphRemake = function () {
            // Start a timer to wait before calling the routine that remakes the graph.
            // This way we're not bothering the user with the long redraw process when
            // they are making fast edits.
            if (this.graphRefreshTimerID) {
                clearTimeout(this.graphRefreshTimerID);
            }
            if (this.graphEnabled) {
                this.graphRefreshTimerID = setTimeout(this.remakeGraphArea.bind(this), 700);
            }
        };
        IdentifyStructuresStep.prototype.remakeGraphArea = function () {
            $('#processingStep2ResultsLabel').removeClass('off');
            var mode = this.selectMajorKindStep.interpretationMode;
            this.graphRefreshTimerID = 0;
            if (!EDDATDGraphing || !this.graphEnabled) {
                return;
            }
            EDDATDGraphing.clearAllSets();
            var sets = this.graphSets;
            // If we're not in either of these modes, drawing a graph is nonsensical.
            if (mode === "std" || mode === 'biolector' || mode === 'hplc') {
                sets.forEach(function (set) { return EDDATDGraphing.addNewSet(set); });
            }
            EDDATDGraphing.drawSets();
            $('#processingStep2ResultsLabel').addClass('off');
        };
        IdentifyStructuresStep.prototype.getUserWarnings = function () {
            return this.warningMessages;
        };
        IdentifyStructuresStep.prototype.getUserErrors = function () {
            return this.errorMessages;
        };
        IdentifyStructuresStep.prototype.requiredInputsProvided = function () {
            for (var row in this.pulldownObjects) {
                var rowInactivated = !this.activeRowFlags[row];
                if (rowInactivated) {
                    continue;
                }
                var inputSelector = this.pulldownObjects[row];
                var comboBox = $(inputSelector);
                if (comboBox.val() == this.DEFAULT_STEP3_PULLDOWN_VALUE) {
                    return false;
                }
            }
            return this.parsedSets.length > 0;
        };
        return IdentifyStructuresStep;
    })();
    EDDTableImport.IdentifyStructuresStep = IdentifyStructuresStep;
    // The class responsible for everything in the "Step 4" box that you see on the data import page.
    var TypeDisambiguationStep = (function () {
        function TypeDisambiguationStep(selectMajorKindStep, identifyStructuresStep, nextStepCallback) {
            this.requiredInputSelectors = []; //selectors for all inputs that must have a value
            // for this step to be complete (some are hidden / not directly adjusted by the user)
            this.allUserInputSelectors = [];
            this.masterInputSelectors = [];
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
            this.errorMessages = [];
            this.warningMessages = [];
            // set up a listener to recreate the controls for this step based on a change to any
            // of the "master" inputs that requires rebuilding the form for this step.
            // Note that here and below we use 'input' since it makes the GUI more responsive
            // to user changes. A separate timer we've added prevents reprocessing the form too
            // many times.
            var reDoStepOnChange = ['#masterAssay', '#masterLine', '#masterMComp', '#masterMType', '#masterMUnits'];
            $(reDoStepOnChange.join(',')).on('input', this.changedAnyMasterPulldown.bind(this));
            this.masterInputSelectors = ['#masterTimestamp'].concat(reDoStepOnChange);
            $('#masterTimestamp').on('input', this.queueReparseThisStep.bind(this));
            $('#resetstep4').on('click', this.resetDisambiguationFields.bind(this));
            // enable autocomplete on statically defined fields
            EDD_auto.setup_field_autocomplete('#masterMComp', 'MeasurementCompartment');
            EDD_auto.setup_field_autocomplete('#masterMType', 'GenericOrMetabolite', EDDData.MetaboliteTypes || {});
            EDD_auto.setup_field_autocomplete('#masterMUnits', 'MeasurementUnit');
        }
        /**
         * Tests whether the provided element has CSS class with the provided name
         */
        TypeDisambiguationStep.prototype.isClassOn = function (element, className) {
            var classList = element.attr("class").split("\s+");
            return classList.indexOf(className) > -1;
        };
        TypeDisambiguationStep.prototype.setAllInputsEnabled = function (enabled) {
            var selectorsList = this.allUserInputSelectors.join(',');
            if (enabled) {
                $(selectorsList).removeAttr('disabled');
            }
            else {
                $(selectorsList).attr('disabled', 'disabled');
            }
        };
        TypeDisambiguationStep.prototype.previousStepChanged = function () {
            this.disableInputDuringProcessing();
            var assayIn;
            var currentAssays;
            var masterP = this.selectMajorKindStep.masterProtocol; // Shout-outs to a mid-grade rapper
            if (this.protocolCurrentlyDisplayed != masterP) {
                this.protocolCurrentlyDisplayed = masterP;
                // We deal with recreating this pulldown here, instead of in remakeAssaySection(),
                // because remakeAssaySection() is called by reconfigure(), which is called
                // when other UI in this step changes.  This pulldown is NOT affected by changes to
                // the other UI, so it would be pointless to remake it in response to them.
                assayIn = $('#masterAssay').empty();
                $('<option>').text('(Create New)').appendTo(assayIn).val('named_or_new').prop('selected', true);
                currentAssays = ATData.existingAssays[masterP] || [];
                currentAssays.forEach(function (id) {
                    var assay = EDDData.Assays[id], line = EDDData.Lines[assay.lid], protocol = EDDData.Protocols[assay.pid];
                    $('<option>').appendTo(assayIn).val('' + id).text([
                        line.name, protocol.name, assay.name].join('-'));
                });
                // Always reveal this, since the default for the Assay pulldown is always 'new'.
                $('#masterLineSpan').removeClass('off');
            }
            this.queueReconfigure();
        };
        // Start a timer to wait before calling the reconfigure routine.
        // This way we condense multiple possible events from the radio buttons and/or pulldown into one.
        TypeDisambiguationStep.prototype.queueReconfigure = function () {
            this.disableInputDuringProcessing();
            if (this.inputRefreshTimerID) {
                clearTimeout(this.inputRefreshTimerID);
            }
            // long timeout so we don't interfere with ongoing user edits
            this.inputRefreshTimerID = setTimeout(this.reconfigure.bind(this), 500);
        };
        TypeDisambiguationStep.prototype.queueReparseThisStep = function () {
            if (this.thisStepInputTimerID) {
                clearTimeout(this.thisStepInputTimerID);
            }
            this.thisStepInputTimerID = setTimeout(this.reparseThisStep.bind(this), 500);
        };
        TypeDisambiguationStep.prototype.reparseThisStep = function () {
            this.createSetsForSubmission();
            this.nextStepCallback();
        };
        TypeDisambiguationStep.prototype.disableInputDuringProcessing = function () {
            var hasRequiredInitialInputs = this.identifyStructuresStep.requiredInputsProvided();
            if (hasRequiredInitialInputs) {
                $('#emptyDisambiguationLabel').addClass('off');
            }
            $('#processingStep3Label').toggleClass('off', !hasRequiredInitialInputs);
            this.setAllInputsEnabled(false);
        };
        // Create the Step 4 tables:  Sets of rows, one for each y-axis column of values,
        // where the user can fill out additional information for the pasted table.
        TypeDisambiguationStep.prototype.reconfigure = function () {
            var _this = this;
            var startTime = new Date();
            console.log("Start of TypeDisambiguationStep.reconfigure()");
            this.requiredInputSelectors = [];
            var mode = this.selectMajorKindStep.interpretationMode;
            var parsedSets = this.identifyStructuresStep.parsedSets;
            var seenAnyTimestamps = this.identifyStructuresStep.seenAnyTimestamps;
            this.allUserInputSelectors = [].concat(this.masterInputSelectors);
            // Hide all the subsections by default
            $('#disambiguateLinesSection').addClass('off');
            $('#masterLineDiv').addClass('off');
            $('#disambiguateAssaysSection').addClass('off');
            $('#masterAssayLineDiv').addClass('off');
            $('#disambiguateMeasurementsSection').addClass('off');
            $('#masterMTypeDiv').addClass('off');
            $('#disambiguateMetadataSection').addClass('off');
            var hasRequiredInitialInput = this.identifyStructuresStep.requiredInputsProvided();
            // If parsed data exists, but we haven't seen a single timestamp, show the "master
            // timestamp" input.
            $('#masterTimestampDiv').toggleClass('off', (!hasRequiredInitialInput) || seenAnyTimestamps || (this.identifyStructuresStep.parsedSets.length === 0));
            // Call subroutines for each of the major sections
            if (mode === "biolector") {
                this.remakeLineSection();
            }
            else {
                this.remakeAssaySection();
            }
            this.remakeMeasurementSection();
            this.remakeMetadataSection();
            // add a listener to all the required input fields so we can detect when they're changed
            // and know whether or not to allow continuation to the subsequent step
            $(this.requiredInputSelectors.join(',')).on('input', function () {
                _this.queueReparseThisStep();
            });
            $('#emptyDisambiguationLabel').toggleClass('off', hasRequiredInitialInput);
            $('#processingStep3Label').addClass('off');
            this.setAllInputsEnabled(true);
            var endTime = new Date();
            var elapsedSeconds = (new Date().getTime() - startTime.getTime()) / 1000;
            console.log("End of TypeDisambiguationStep.reconfigure(). Elapsed time: ", elapsedSeconds, " s. Calling next step.");
            this.nextStepCallback();
        };
        // TODO: This function should reset all the disambiguation fields to the values
        // that were auto-detected in the last refresh of the object.
        TypeDisambiguationStep.prototype.resetDisambiguationFields = function () {
            // Get to work!!
        };
        // If the previous step found Line names that need resolving, and the interpretation mode in Step 1
        // warrants resolving Lines independent of Assays, we create this section.
        // The point is that if we connect unresolved Line strings on their own, the unresolved Assay strings
        // can be used to create multiple new Assays with identical names under a range of Lines.
        // This means users can create a matrix of Line/Assay combinations, rather than a one-dimensional
        // resolution where unique Assay names must always point to one unique Assay record.
        TypeDisambiguationStep.prototype.remakeLineSection = function () {
            var _this = this;
            var table, body;
            var uniqueLineNames = this.identifyStructuresStep.uniqueLineNames;
            var startTime = new Date();
            console.log("Start of TypeDisambiguationStep.remakeLineSection()");
            this.currentlyVisibleLineObjSets.forEach(function (disam) {
                disam.rowElementJQ.detach();
            });
            $('#disambiguateLinesTable').remove();
            this.lineObjSets = [];
            if (uniqueLineNames.length === 0) {
                $('#masterLineDiv').removeClass('off');
                console.log("End of TypeDisambiguationStep.remakeLineSection() -- no unique line" +
                    " names to process.");
                return;
            }
            this.currentlyVisibleLineObjSets = [];
            var t = this;
            ////////////////////////////////////////////////////////////////////////////////////////
            // Set up the table and column headers
            ////////////////////////////////////////////////////////////////////////////////////////
            table = $('<table>')
                .attr({ 'id': 'disambiguateLinesTable', 'cellspacing': 0 })
                .appendTo($('#disambiguateLinesSection').removeClass('off'))
                .on('change', 'select', function (ev) {
                t.userChangedLineDisam(ev.target);
            })[0];
            body = $('<tbody>').appendTo(table)[0];
            uniqueLineNames.forEach(function (name, i) {
                var disam, row, defaultSel, cell, select;
                disam = _this.lineObjSets[name];
                if (!disam) {
                    disam = {};
                    defaultSel = _this.disambiguateAnAssayOrLine(name, i);
                    // First make a table row, and save a reference to it
                    row = body.insertRow();
                    disam.rowElementJQ = $(row);
                    // Next, add a table cell with the string we are disambiguating
                    $('<div>').text(name).appendTo(row.insertCell());
                    // Now build another table cell that will contain the pulldowns
                    cell = $(row.insertCell()).css('text-align', 'left');
                    var lineNameInput = $('<input type="text" class="autocomp autocomp_user' +
                        ' ui-autocomplete-input">').appendTo(cell).data('setByUser', false).attr('name', 'disamLineInput' + i);
                    var selectedLineIdInput = $('<input type=hidden>').appendTo(cell).attr('id', 'disamLine' + i).attr('name', 'disamLine' + i).val("named_or_new");
                    disam.selectLineJQElement = {
                        "nameInput": lineNameInput,
                        "selectedId": selectedLineIdInput,
                        "visibleIndex": i
                    };
                    $('<option>').text('(Create New)').appendTo(select).val('new')
                        .prop('selected', !defaultSel.lineID);
                    (ATData.existingLines || []).forEach(function (line) {
                        $('<option>').text(line.n)
                            .appendTo(select).val(line.id.toString())
                            .prop('selected', defaultSel.lineID === line.id);
                    });
                    _this.lineObjSets[name] = disam;
                }
                disam.rowElementJQ.appendTo(body);
                _this.currentlyVisibleLineObjSets.push(disam);
            });
            var endTime = new Date();
            var elapsedSeconds = endTime.getTime() - startTime.getTime();
            console.log("End of TypeDisambiguationStep.remakeLineSection(). Elapsed time: ", elapsedSeconds, " s");
        };
        // If the previous step found Line or Assay names that need resolving, put together a disambiguation section
        // for Assays/Lines.
        // Keep a separate set of correlations between strings and pulldowns for each Protocol,
        // since the same string can match different Assays, and the pulldowns will have different content, in each Protocol.
        // If the previous step didn't find any Line or Assay names that need resolving,
        // reveal the pulldowns for selecting a master Line/Assay, leaving the table empty, and return.
        TypeDisambiguationStep.prototype.remakeAssaySection = function () {
            var _this = this;
            var table, tableBody;
            var uniqueAssayNames = this.identifyStructuresStep.uniqueAssayNames;
            var masterProtocol = this.protocolCurrentlyDisplayed;
            var startTime = new Date();
            console.log("Start of TypeDisambiguationStep.remakeAssaySection()");
            this.currentlyVisibleAssayObjSets.forEach(function (disam) {
                disam.rowElementJQ.detach();
            });
            $('#disambiguateAssaysTable').remove();
            // remove stale data from previous run of this step
            this.assayObjSets = {};
            this.assayObjSets[masterProtocol] = {};
            if ((!this.identifyStructuresStep.requiredInputsProvided()) || this.identifyStructuresStep.parsedSets.length === 0) {
                console.log("End of TypeDisambiguationStep.remakeAssaySection() -- no input data" +
                    " to process");
                return;
            }
            if (uniqueAssayNames.length === 0) {
                console.log("End of TypeDisambiguationStep.remakeAssaySection() -- no unique" +
                    " assay names to process");
                $('#masterAssayLineDiv').removeClass('off');
            }
            ////////////////////////////////////////////////////////////////////////////////////////
            // Create the table
            ////////////////////////////////////////////////////////////////////////////////////////
            this.currentlyVisibleAssayObjSets = [];
            var t = this;
            table = $('<table>')
                .attr({ 'id': 'disambiguateAssaysTable', 'cellspacing': 0 })
                .appendTo($('#disambiguateAssaysSection').removeClass('off'))
                .on('change', 'select', function (ev) {
                t.userChangedAssayDisam(ev.target);
            })[0];
            tableBody = $('<tbody>').appendTo(table)[0];
            ////////////////////////////////////////////////////////////////////////////////////////
            // Create a table row for each unique assay name
            ////////////////////////////////////////////////////////////////////////////////////////
            var nRows = 0;
            var nControls = 4;
            var nColumns = 5;
            var maxRowCreationSeconds = 0;
            var totalRowCreationSeconds = 0;
            uniqueAssayNames.forEach(function (assayName, i) {
                var rowCreationStartTime = new Date();
                var disam, row, defaultSelection, cell, aSelect, lineNameInput;
                var selectedLineIdInput;
                disam = _this.assayObjSets[masterProtocol][assayName];
                if (!disam) {
                    disam = {};
                    defaultSelection = _this.disambiguateAnAssayOrLine(assayName, i);
                    // First make a table row, and save a reference to it
                    row = tableBody.insertRow();
                    nRows++;
                    disam.rowElementJQ = $(row);
                    // Next, add a table cell with the string we are disambiguating
                    $('<div>').text(assayName).appendTo(row.insertCell());
                    /////////////////////////////////////////////////////////////////////////////
                    // Set up a combo box for selecting the assay
                    /////////////////////////////////////////////////////////////////////////////
                    cell = $(row.insertCell()).css('text-align', 'left');
                    var assayId = 'disamAssay' + i;
                    var assaySelector = '#' + assayId;
                    _this.requiredInputSelectors.push(assaySelector);
                    _this.allUserInputSelectors.push(assaySelector);
                    aSelect = $('<select>').appendTo(cell)
                        .data({ 'setByUser': false })
                        .attr('name', 'disamAssay' + i).attr('id', assayId);
                    disam.selectAssayJQElement = aSelect;
                    $('<option>').text('(Create New Assay)').appendTo(aSelect).val('named_or_new')
                        .prop('selected', !defaultSelection.assayID);
                    // add options to the assay combo box
                    (ATData.existingAssays[masterProtocol] || []).forEach(function (id) {
                        var assay, line, protocol;
                        assay = EDDData.Assays[id];
                        line = EDDData.Lines[assay.lid];
                        protocol = EDDData.Protocols[assay.pid];
                        $('<option>').text([line.name, protocol.name, assay.name].join('-'))
                            .appendTo(aSelect).val(id.toString())
                            .prop('selected', defaultSelection.assayID === id);
                    });
                    // a span to contain the text label for the Line pulldown, and the pulldown itself
                    cell = $('<span>').text('for Line:').toggleClass('off', !!defaultSelection.assayID)
                        .appendTo(cell);
                    /////////////////////////////////////////////////////////////////////////////
                    // Set up an autocomplete for the line (autocomplete is important for
                    // efficiency for studies with many lines).
                    /////////////////////////////////////////////////////////////////////////////
                    _this.appendLineAutoselect(cell, disam, defaultSelection, i);
                    _this.assayObjSets[masterProtocol][assayName] = disam;
                }
                disam.selectAssayJQElement.data({ 'visibleIndex': i });
                disam.rowElementJQ.appendTo(tableBody);
                _this.currentlyVisibleAssayObjSets.push(disam);
                var rowCreationEndTime = new Date();
                var rowCreationElapsedSeconds = (rowCreationEndTime.getTime() - rowCreationStartTime.getTime()) / 1000;
                totalRowCreationSeconds += rowCreationElapsedSeconds;
            });
            var avgRowCreationSeconds = totalRowCreationSeconds / nRows;
            var endTime = new Date();
            var elapsedSeconds = (endTime.getTime() - startTime.getTime()) / 1000;
            console.log("End of TypeDisambiguationStep.remakeAssaySection(). Table is ", nRows, " rows X ", nColumns, " cols, with ", ATData.existingLines.length, " line options. Elapsed time: " +
                " time: ", elapsedSeconds, " s. Avg row creation time: ", avgRowCreationSeconds, " s");
        };
        TypeDisambiguationStep.prototype.appendLineAutoselect = function (parentElement, disam, defaultSelection, i) {
            // create a text input to gather user input
            var lineInputId = 'disamLineInput' + i;
            var lineInputSelector = '#' + lineInputId;
            var lineNameInput = $('<input type="text" class="autocomp autocomp_user' +
                '" ui-autocomplete-input">')
                .data('setByUser', false)
                .attr('name', lineInputId)
                .prop('id', lineInputId)
                .val("(Create New)")
                .appendTo(parentElement);
            this.allUserInputSelectors.push(lineInputSelector);
            // create a hidden form field to store the selected value
            var selectedLineIdInput = $('<input type=hidden>')
                .appendTo(parentElement)
                .attr('id', 'disamLine' + i)
                .attr('name', 'disamLine' + i)
                .val("new");
            this.requiredInputSelectors.push(lineInputSelector);
            // set up autocomplete for using controls created above
            var model_class_name = "StudyLine";
            var search_uri = "/study/" + EDDData.currentStudyID + "/lines";
            EDD_auto.setup_field_autocomplete(lineNameInput, model_class_name, EDDData.Lines, {}, [{ "name": "(Create New)", "id": "new" }], search_uri);
            // save references to both the input and the hidden form field that stores the
            // selected value
            disam.selectLineJQElement = {
                "nameInput": lineNameInput,
                "selectedId": selectedLineIdInput,
            };
            // auto-select the line name if possible
            if (defaultSelection.lineID) {
                // search for the line ID corresponding to this name.
                // ATData.existingLines is of type {id: number; n: string;}[]
                (ATData.existingLines || []).forEach(function (line) {
                    if (defaultSelection.lineID === line.id) {
                        lineNameInput.val(line.n);
                        selectedLineIdInput.val(line.id.toString());
                        return false; // stop looping
                    }
                });
            }
        };
        TypeDisambiguationStep.prototype.remakeMeasurementSection = function () {
            var _this = this;
            var body, row;
            var mode = this.selectMajorKindStep.interpretationMode;
            var uniqueMeasurementNames = this.identifyStructuresStep.uniqueMeasurementNames;
            var seenAnyTimestamps = this.identifyStructuresStep.seenAnyTimestamps;
            var startTime = new Date();
            console.log("Start of TypeDisambiguationStep.remakeMeasurementSection()");
            $('#disambiguateMeasurementsSection').addClass('off');
            $('#masterMTypeDiv').addClass('off');
            var bodyJq = $('#disambiguateMeasurementsTable tbody');
            bodyJq.empty();
            this.currentlyVisibleMeasurementObjSets.forEach(function (disam) {
                disam.rowElementJQ.detach();
            });
            // If in 'Transcription' or 'Proteomics' mode, there are no measurement types involved.
            // skip the measurement section, and provide statistics about the gathered records.
            if (mode === "tr" || mode === "pr") {
                console.log("End of TypeDisambiguationStep.remakeMeasurementSection() - not" +
                    " required for mode ", mode);
                return;
            }
            // No measurements for disambiguation, have timestamp data:  That means we need to choose one measurement.
            // You might think that we should display this even without timestamp data, to handle the case where we're importing
            // a single measurement type for a single timestamp...  But that would be a 1-dimensional import, since there is only
            // one other object with multiple types to work with (lines/assays).  We're not going to bother supporting that.
            if (uniqueMeasurementNames.length === 0 && seenAnyTimestamps) {
                console.log("End of TypeDisambiguationStep.remakeMeasurementSection() - no" +
                    " measurements for disambiguation.");
                return;
            }
            // put together a disambiguation section for measurement types
            var t = this;
            body = ($('#disambiguateMeasurementsTable').children().first()[0]);
            this.currentlyVisibleMeasurementObjSets = []; // For use in cascading user settings
            uniqueMeasurementNames.forEach(function (name, i) {
                var disam;
                disam = _this.measurementObjSets[name];
                if (disam && disam.rowElementJQ) {
                    disam.rowElementJQ.appendTo(body);
                }
                else {
                    disam = {};
                    row = body.insertRow();
                    disam.rowElementJQ = $(row);
                    $('<div>').text(name).appendTo(row.insertCell());
                    // create autocompletes
                    ['compObj', 'typeObj', 'unitsObj'].forEach(function (auto) {
                        var cell = $(row.insertCell()).addClass('disamDataCell');
                        disam[auto] = EDD_auto.create_autocomplete(cell).data('type', auto);
                        _this.allUserInputSelectors.push(disam[auto]);
                    });
                    disam.typeHiddenObj = disam.typeObj.attr('size', 45).next();
                    disam.compHiddenObj = disam.compObj.attr('size', 4).next();
                    disam.unitsHiddenObj = disam.unitsObj.attr('size', 10).next();
                    _this.requiredInputSelectors.push(disam.typeHiddenObj);
                    _this.requiredInputSelectors.push(disam.compHiddenObj);
                    _this.requiredInputSelectors.push(disam.unitsHiddenObj);
                    $(row).on('change', 'input[type=hidden]', function (ev) {
                        // only watch for changes on the hidden portion, let autocomplete work
                        t.userChangedMeasurementDisam(ev.target);
                    });
                    EDD_auto.setup_field_autocomplete(disam.compObj, 'MeasurementCompartment', _this.autoCache.comp);
                    EDD_auto.setup_field_autocomplete(disam.typeObj, 'GenericOrMetabolite', _this.autoCache.metabolite);
                    EDD_auto.initial_search(disam.typeObj, name);
                    EDD_auto.setup_field_autocomplete(disam.unitsObj, 'MeasurementUnit', _this.autoCache.unit);
                    _this.measurementObjSets[name] = disam;
                }
                // TODO sizing should be handled in CSS
                disam.compObj.data('visibleIndex', i);
                disam.typeObj.data('visibleIndex', i);
                disam.unitsObj.data('visibleIndex', i);
                // If we're in MDV mode, the units pulldowns are irrelevant.
                disam.unitsObj.toggleClass('off', mode === 'mdv');
                _this.currentlyVisibleMeasurementObjSets.push(disam);
            });
            this.checkAllMeasurementCompartmentDisam();
            $('#disambiguateMeasurementsSection').removeClass('off');
            var endTime = new Date();
            var elapsedSeconds = (endTime.getTime() - startTime.getTime()) / 1000;
            console.log("End of TypeDisambiguationStep.remakeMeasurementSection(). Elapsed time:" +
                " ", elapsedSeconds, " s.");
        };
        TypeDisambiguationStep.prototype.remakeMetadataSection = function () {
            var _this = this;
            var table, body, row;
            var startTime = new Date();
            console.log("Start of TypeDisambiguationStep.remakeMetadataSection()");
            var uniqueMetadataNames = this.identifyStructuresStep.uniqueMetadataNames;
            if (uniqueMetadataNames.length < 1) {
                console.log("End of TypeDisambiguationStep.remakeMetadataSection(). Returning" +
                    " early");
                return;
            }
            $('#disambiguateMetadataTable').remove();
            // put together a disambiguation section for metadata
            table = $('<table>')
                .attr({ 'id': 'disambiguateMetadataTable', 'cellspacing': 0 })
                .appendTo($('#disambiguateMetadataSection').removeClass('off'))
                .on('change', 'input', function (ev) {
                // should there be event handling here ?
            })[0];
            body = $('<tbody>').appendTo(table)[0];
            uniqueMetadataNames.forEach(function (name, i) {
                var disam;
                disam = _this.metadataObjSets[name];
                if (disam && disam.rowElementJQ) {
                    disam.rowElementJQ.appendTo(body);
                }
                else {
                    disam = {};
                    row = body.insertRow();
                    disam.rowElementJQ = $(row);
                    $('<div>').text(name).appendTo(row.insertCell());
                    disam.metaObj = EDD_auto.create_autocomplete(row.insertCell()).val(name);
                    disam.metaHiddenObj = disam.metaObj.next();
                    _this.allUserInputSelectors.push(disam.metaObj);
                    _this.requiredInputSelectors.push(disam.metaHiddenObj);
                    _this.metadataObjSets[name] = disam;
                }
                disam.metaObj.attr('name', 'disamMeta' + i).addClass('autocomp_altype')
                    .next().attr('name', 'disamMetaHidden' + i);
                EDD_auto.setup_field_autocomplete(disam.metaObj, 'AssayLineMetadataType', _this.autoCache.meta);
            });
            var endTime = new Date();
            var elapsedSeconds = (endTime.getTime() - startTime.getTime()) / 1000;
            console.log("End of TypeDisambiguationStep.remakeMetadataSection(). Elapsed time: ", elapsedSeconds, " s.");
        };
        // We call this when any of the 'master' pulldowns are changed in Step 4.
        // Such changes may affect the available contents of some of the pulldowns in the step.
        TypeDisambiguationStep.prototype.changedAnyMasterPulldown = function () {
            // Show the master line dropdown if the master assay dropdown is set to new
            $('#masterLineSpan').toggleClass('off', $('#masterAssay').val() !== 'named_or_new');
            this.queueReconfigure();
        };
        // If the pulldown is being set to 'new', walk down the remaining pulldowns in the section,
        // in order, setting them to 'new' as well, stopping just before any pulldown marked as
        // being 'set by the user'.
        TypeDisambiguationStep.prototype.userChangedLineDisam = function (lineEl) {
            var changed, v;
            changed = $(lineEl).data('setByUser', true);
            if (changed.val() !== 'new') {
                // stop here for anything other than 'new'; only 'new' cascades to following pulldowns
                return false;
            }
            v = changed.data('visibleIndex') || 0;
            this.currentlyVisibleLineObjSets.slice(v).forEach(function (obj) {
                var textInput = obj.selectLineJQElement.nameInput;
                if (textInput.data('setByUser')) {
                    return;
                }
                // set dropdown to 'new' and reveal the line autoselect
                textInput.val('new').next().removeClass('off');
            });
            return false;
        };
        // This function serves two purposes.
        // 1. If the given Assay disambiguation pulldown is being set to 'new', reveal the adjacent
        //    Line pulldown, otherwise hide it.
        // 2. If the pulldown is being set to 'new', walk down the remaining pulldowns in the section,
        //    in order, setting them to 'new' as well, stopping just before any pulldown marked as
        //    being 'set by the user'.
        TypeDisambiguationStep.prototype.userChangedAssayDisam = function (assayEl) {
            var startTime = new Date();
            console.log("Start of TypeDisambiguationStep.userChangedAssayDisam()");
            var changed, v;
            changed = $(assayEl).data('setByUser', true);
            // The span with the corresponding Line pulldown is always right next to the Assay pulldown
            changed.next().toggleClass('off', changed.val() !== 'named_or_new');
            if (changed.val() !== 'named_or_new') {
                // stop here for anything other than 'new'; only 'new' cascades to following pulldowns
                console.log("End of TypeDisambiguationStep.userChangedAssayDisam()");
                return false;
            }
            v = changed.data('visibleIndex') || 0;
            this.currentlyVisibleAssayObjSets.slice(v).forEach(function (obj) {
                var assaySelect = obj.selectAssayJQElement;
                if (assaySelect.data('setByUser')) {
                    return;
                }
                // set assay dropdown to 'new' and reveal the line autocomplete
                assaySelect.val('named_or_new').next().removeClass('off');
            });
            var endTime = new Date();
            var elapsedSeconds = (endTime.getTime() - startTime.getTime()) / 1000;
            console.log("End of TypeDisambiguationStep.userChangedAssayDisam(). Elapsed time: ", elapsedSeconds, " s");
            return false;
        };
        TypeDisambiguationStep.prototype.userChangedMeasurementDisam = function (element) {
            console.log('changed');
            var hidden, auto, type, i;
            hidden = $(element);
            auto = hidden.prev();
            type = auto.data('type');
            if (type === 'compObj' || type === 'unitsObj') {
                i = auto.data('setByUser', true).data('visibleIndex') || 0;
                this.currentlyVisibleMeasurementObjSets.slice(i).some(function (obj) {
                    var following = $(obj[type]);
                    if (following.length === 0 || following.data('setByUser')) {
                        return true; // break; for the Array.some() loop
                    }
                    // using placeholder instead of val to avoid triggering autocomplete change
                    following.attr('placeholder', auto.val());
                    following.next().val(hidden.val());
                    return false;
                });
            }
            // not checking typeObj; form submit sends selected types
            this.checkAllMeasurementCompartmentDisam();
        };
        // Run through the list of currently visible measurement disambiguation form elements,
        // checking to see if any of the 'compartment' elements are set to a non-blank value.
        // If any are, and we're in MDV document mode, display a warning that the user should
        // specify compartments for all their measurements.
        TypeDisambiguationStep.prototype.checkAllMeasurementCompartmentDisam = function () {
            var allSet;
            var mode = this.selectMajorKindStep.interpretationMode;
            allSet = this.currentlyVisibleMeasurementObjSets.every(function (obj) {
                var hidden = obj.compHiddenObj;
                if (obj.compObj.data('setByUser') || (hidden.val() && hidden.val() !== '0')) {
                    return true;
                }
                return false;
            });
            $('#noCompartmentWarning').toggleClass('off', mode !== 'mdv' || allSet);
        };
        TypeDisambiguationStep.prototype.disambiguateAnAssayOrLine = function (assayOrLine, currentIndex) {
            console.log("Start of TypeDisambiguationStep.disambiguateAnAssayOrLine()");
            var startTime = new Date();
            var selections, highest, assays;
            selections = {
                lineID: 0,
                assayID: 0
            };
            highest = 0;
            // ATData.existingAssays is type {[index: string]: number[]}
            assays = ATData.existingAssays[this.selectMajorKindStep.masterProtocol] || [];
            assays.every(function (id, i) {
                var assay, line, protocol, name;
                assay = EDDData.Assays[id];
                line = EDDData.Lines[assay.lid];
                protocol = EDDData.Protocols[assay.pid];
                name = [line.name, protocol.name, assay.name].join('-');
                if (assayOrLine.toLowerCase() === name.toLowerCase()) {
                    // The full Assay name, even case-insensitive, is the best match
                    selections.assayID = id;
                    return false; // do not need to continue
                }
                else if (highest < 0.8 && assayOrLine === assay.name) {
                    // An exact-case match with the Assay name fragment alone is second-best.
                    highest = 0.8;
                    selections.assayID = id;
                }
                else if (highest < 0.7 && assay.name.indexOf(assayOrLine) >= 0) {
                    // Finding the whole string inside the Assay name fragment is pretty good
                    highest = 0.7;
                    selections.assayID = id;
                }
                else if (highest < 0.6 && line.name.indexOf(assayOrLine) >= 0) {
                    // Finding the whole string inside the originating Line name is good too.
                    // It means that the user may intend to pair with this Assay even though the
                    // Assay name is different.  
                    highest = 0.6;
                    selections.assayID = id;
                }
                else if (highest < 0.4 &&
                    (new RegExp('(^|\\W)' + assay.name + '(\\W|$)', 'g')).test(assayOrLine)) {
                    // Finding the Assay name fragment within the whole string, as a whole word, is our
                    // last option.
                    highest = 0.4;
                    selections.assayID = id;
                }
                else if (highest < 0.3 && currentIndex === i) {
                    // If all else fails, choose Assay of current index in sorted order.
                    highest = 0.3;
                    selections.assayID = id;
                }
                return true;
            });
            // Now we repeat the practice, separately, for the Line pulldown.
            highest = 0;
            // ATData.existingLines is type {id: number; n: string;}[]
            (ATData.existingLines || []).every(function (line, i) {
                if (assayOrLine === line.n) {
                    // The Line name, case-sensitive, is the best match
                    selections.lineID = line.id;
                    return false; // do not need to continue
                }
                else if (highest < 0.8 && assayOrLine.toLowerCase() === line.n.toLowerCase()) {
                    // The same thing case-insensitive is second best.
                    highest = 0.8;
                    selections.lineID = line.id;
                }
                else if (highest < 0.7 && assayOrLine.indexOf(line.n) >= 0) {
                    // Finding the Line name within the string is odd, but good.
                    highest = 0.7;
                    selections.lineID = line.id;
                }
                else if (highest < 0.6 && line.n.indexOf(assayOrLine) >= 0) {
                    // Finding the string within the Line name is also good.
                    highest = 0.6;
                    selections.lineID = line.id;
                }
                else if (highest < 0.5 && currentIndex === i) {
                    // Again, if all else fails, just choose the Line that matches the current index
                    // in sorted order, in a loop.
                    highest = 0.5;
                    selections.lineID = line.id;
                }
                return true;
            });
            var endTime = new Date();
            var elapsedSeconds = (endTime.getTime() - startTime.getTime()) / 1000;
            console.log("End of TypeDisambiguationStep.disambiguateAnAssayOrLine(). Elapsed" +
                " time: ", elapsedSeconds, " s");
            return selections;
        };
        TypeDisambiguationStep.prototype.createSetsForSubmission = function () {
            var _this = this;
            this.errorMessages = [];
            this.warningMessages = [];
            var startTime = new Date();
            console.log("Start of TypeDisambiguationStep.createSetsForSubmission().");
            // From Step 1
            var mode = this.selectMajorKindStep.interpretationMode;
            var masterProtocol = $("#masterProtocol").val();
            if (masterProtocol === DEFAULT_MASTER_PROTOCOL) {
                masterProtocol = null;
            }
            // From Step 3
            var seenAnyTimestamps = this.identifyStructuresStep.seenAnyTimestamps;
            var parsedSets = this.identifyStructuresStep.parsedSets;
            // From this Step
            var masterTime = parseFloat($('#masterTimestamp').val());
            var masterLine = $('#masterLine').val();
            var masterAssayLine = $('#masterAssayLine').val();
            var masterAssay = $('#masterAssay').val();
            var masterMType = $('#masterMTypeValue').val();
            var masterMComp = $('#masterMCompValue').val();
            var masterMUnits = $('#masterMUnitsValue').val();
            var resolvedSets = [];
            var droppedDatasetsForMissingTime = 0;
            parsedSets.forEach(function (set, c) {
                var resolvedSet;
                var line_id = 'new'; // A convenient default
                var assay_id = 'named_or_new';
                var measurement_id = null;
                var compartment_id = null;
                var units_id = null;
                // In modes where we resolve measurement types in the client UI, go with the master values by default.
                if (mode === "biolector" || mode === "std" || mode === "mdv" || mode === "hplc") {
                    measurement_id = masterMType;
                    compartment_id = masterMComp;
                    units_id = masterMUnits;
                }
                var data = set.data;
                var metaData = {};
                var metaDataPresent = false;
                if (mode === "biolector") {
                    line_id = masterLine;
                    assay_id = "named_or_new"; // Tells the server to attempt to resolve directly against the name, or make a new Assay
                    // If we have a valid, specific Line name, look for a disambiguation field that matches it.
                    if (set.line_name !== null) {
                        var disam = _this.lineObjSets[set.line_name];
                        if (disam) {
                            var lineIdInput = disam.selectLineJQElement.selectedId;
                            line_id = lineIdInput.val();
                        }
                    }
                }
                else {
                    line_id = masterAssayLine;
                    assay_id = masterAssay;
                    if (set.assay_name !== null && masterProtocol) {
                        var disam = _this.assayObjSets[masterProtocol][set.assay_name];
                        if (disam) {
                            assay_id = disam.selectAssayJQElement.val();
                            var lineIdInput = disam.selectLineJQElement.selectedId;
                            line_id = lineIdInput.val();
                        }
                    }
                }
                // Same for measurement name, but resolve all three measurement fields if we find a match,
                // and only if we are resolving measurement types client-side.
                if (mode === "biolector" || mode === "std" || mode === "mdv" || mode === 'hplc') {
                    if (set.measurement_name !== null) {
                        var disam = _this.measurementObjSets[set.measurement_name];
                        if (disam) {
                            measurement_id = disam.typeHiddenObj.val();
                            compartment_id = disam.compHiddenObj.val() || "0";
                            units_id = disam.unitsHiddenObj.val() || "1";
                        }
                    }
                }
                // Any metadata disambiguation fields that are left unresolved, will have their metadata
                // dropped from the import in this step, because this loop is building key-value pairs where
                // the key is the chosen database id of the metadata type.  No id == not added.
                Object.keys(set.metadata_by_name).forEach(function (name) {
                    var disam = _this.metadataObjSets[name];
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
                    }
                    else {
                        data = [];
                        droppedDatasetsForMissingTime++;
                    }
                }
                // If we have no data, and no metadata that survived resolving, don't make the set.
                if (data.length < 1 && !metaDataPresent) {
                    return;
                }
                resolvedSet = {
                    // Copy across the fields from the RawImportSet record
                    kind: set.kind,
                    line_name: set.line_name,
                    assay_name: set.assay_name,
                    measurement_name: set.measurement_name,
                    metadata_by_name: set.metadata_by_name,
                    data: data,
                    // Add new disambiguation-specific fields
                    protocol_id: masterProtocol,
                    line_id: line_id,
                    assay_id: assay_id,
                    measurement_id: measurement_id,
                    compartment_id: compartment_id,
                    units_id: units_id,
                    metadata_by_id: metaData
                };
                resolvedSets.push(resolvedSet);
            });
            // log some debugging output if any data get dropped because of a missing timestamp
            if (droppedDatasetsForMissingTime) {
                if (parsedSets.length === droppedDatasetsForMissingTime) {
                    var msg = "A timestamp is required to complete the import. No included" +
                        " measurement has a time.";
                    console.warn(msg);
                    this.errorMessages.push(new ImportMessage(msg, null, null));
                }
                else {
                    var percentDropped = (droppedDatasetsForMissingTime / parsedSets.length) * 100;
                    var warningMessage = droppedDatasetsForMissingTime + " parsed datasets (" +
                        percentDropped + "%) were dropped because they were missing a timestamp.";
                    console.warn(warningMessage);
                    this.warningMessages.push(new ImportMessage(msg, null, null));
                }
            }
            var endTime = new Date();
            var elapsedSeconds = (endTime.getTime() - startTime.getTime()) / 1000;
            console.log("End of TypeDisambiguationStep.createSetsForSubmission(). Elapsed time: ", elapsedSeconds, " s");
            return resolvedSets;
        };
        TypeDisambiguationStep.prototype.getUserWarnings = function () {
            return this.warningMessages;
        };
        TypeDisambiguationStep.prototype.getUserErrors = function () {
            return this.errorMessages;
            // return [
            //     new ImportMessage('Test Error 1'),
            //     new ImportMessage('Test Error 2'),
            //     new ImportMessage('Test Error 3'),
            //     new ImportMessage('Test Error 4'),
            //     new ImportMessage('Test Error 5'),
            //     new ImportMessage('Test Error 6')
            // ];
        };
        TypeDisambiguationStep.prototype.requiredInputsProvided = function () {
            for (var _i = 0, _a = this.requiredInputSelectors; _i < _a.length; _i++) {
                var selector = _a[_i];
                var input = $(selector);
                if (input.prop('disabled') || !input.val()) {
                    return false;
                }
            }
            return this.requiredInputSelectors.length > 0;
        };
        return TypeDisambiguationStep;
    })();
    EDDTableImport.TypeDisambiguationStep = TypeDisambiguationStep;
    // The class responsible for everything in the "Step 4" box that you see on the data import page.
    // Aggregates & displays a user-relevant/actionable summary of the import process prior to final
    // submission.
    var ReviewStep = (function () {
        function ReviewStep(step1, step2, step3, step4, nextStepCallback) {
            var _this = this;
            this.step1 = step1;
            this.step2 = step2;
            this.step3 = step3;
            this.step4 = step4;
            this.prevSteps = [step1, step2, step3, step4];
            this.nextStepCallback = nextStepCallback;
            this.errorMessages = [];
            this.warningMessages = [];
            this.warningInputs = [];
            this.prevSteps.forEach(function (step, stepIndex) {
                _this.warningInputs[stepIndex] = [];
            });
        }
        ReviewStep.prototype.previousStepChanged = function () {
            var _this = this;
            // re-query each preceding step to get any errorMessages or warningMessages that should be displayed
            // to the user
            this.prevSteps.forEach(function (prevStep, stepIndex) {
                _this.warningMessages[stepIndex] = [].concat(prevStep.getUserWarnings());
                _this.errorMessages[stepIndex] = [].concat(prevStep.getUserErrors());
                _this.warningInputs[stepIndex] = [];
            });
            // build up a short summary section to describe the (potentially large) number of
            // errors / warnings, as well as to give some generally helpful summary (e.g. counts).
            // for starters, we'll only show the summary section with a minimal one-sentence
            // that has directions, though clearly more stuff could be helpful later.
            var totalErrorsCount = this.getMessageCount(this.errorMessages);
            var totalWarningsCount = this.getMessageCount(this.warningMessages);
            var totalMessagesCount = totalErrorsCount + totalWarningsCount;
            var summaryDiv = $('#summaryContentDiv');
            summaryDiv.empty();
            var hasRequiredInitialInputs = this.arePrevStepRequiredInputsProvided();
            var summaryWrapperDiv = $('#reviewSummarySection');
            if (hasRequiredInitialInputs && !totalMessagesCount) {
                $('<p>').text('No errors or warnings! Go ahead and import!').appendTo(summaryDiv);
            }
            $('#completeAllStepsFirstLabel').toggleClass('off', hasRequiredInitialInputs);
            $('#submitForImport').toggleClass('off', !hasRequiredInitialInputs);
            // remake error / warning subsections based on input from previous steps
            var errorsWrapperDiv = $('#reviewErrorsSection');
            var errorsDiv = $('#reviewErrorsContentDiv');
            this.remakeErrorOrWarningSection(errorsWrapperDiv, errorsDiv, this.errorMessages, totalErrorsCount, "errorMessage", [], false);
            var warningsWrapperDiv = $('#reviewWarningsSection');
            var warningsDiv = $('#reviewWarningsContentDiv');
            this.remakeErrorOrWarningSection(warningsWrapperDiv, warningsDiv, this.warningMessages, totalWarningsCount, "warningMessage", this.warningInputs, true);
            this.updateSubmitEnabled();
        };
        ReviewStep.prototype.arePrevStepRequiredInputsProvided = function () {
            for (var _i = 0, _a = this.prevSteps; _i < _a.length; _i++) {
                var prevStep = _a[_i];
                if (!prevStep.requiredInputsProvided()) {
                    return false;
                }
            }
            return true;
        };
        // enable / disable the submit button, depending on whether submission is expected
        // to succeed based on data available in the UI
        ReviewStep.prototype.updateSubmitEnabled = function () {
            var allPrevStepInputsProvided = this.arePrevStepRequiredInputsProvided();
            var allWarningsAcknowledged = this.areAllWarningsAcknowledged();
            var totalErrorsCount = this.getMessageCount(this.errorMessages);
            var submitButton = $('#submitForImport');
            var wasDisabled = submitButton.prop('disabled');
            var disableSubmit = !(allPrevStepInputsProvided && (totalErrorsCount === 0) && allWarningsAcknowledged);
            if (disableSubmit) {
                console.log('Disabling submit'); //TODO: remove debug stmt
                submitButton.attr('disabled', 'disabled');
            }
            else {
                console.log('Enabling submit'); //TODO: remove debug stmt
                submitButton.removeAttr('disabled');
            }
            // briefly highlight the button if it was enabled/disabled
            if ((wasDisabled != disableSubmit) && allPrevStepInputsProvided) {
                submitButton.effect("bounce");
            }
        };
        ReviewStep.prototype.areAllWarningsAcknowledged = function () {
            var index = 0;
            for (var _i = 0, _a = this.warningInputs; _i < _a.length; _i++) {
                var stepWarningInputs = _a[_i];
                for (var _b = 0; _b < stepWarningInputs.length; _b++) {
                    var warningChkbx = stepWarningInputs[_b];
                    index++;
                    if (!warningChkbx.is(':checked')) {
                        console.log('Not all warnings acknowledged. Warning ', index, 'isnt' +
                            ' checked.'); //TODO: remove debug stmt and counter
                        return false;
                    }
                }
            }
            console.log('All warnings acknowledged.'); //TODO: remove debug stmt
            return true;
        };
        ReviewStep.prototype.getMessageCount = function (messagesByStep) {
            var messageCount = 0;
            for (var _i = 0; _i < messagesByStep.length; _i++) {
                var stepMessages = messagesByStep[_i];
                messageCount += stepMessages.length;
            }
            return messageCount;
        };
        ReviewStep.prototype.remakeErrorOrWarningSection = function (wrapperDivSelector, contentDivSelector, userMessages, messageCount, messageCssClass, inputs, createCheckboxes) {
            var _this = this;
            contentDivSelector.empty();
            var hasRequiredInitialInputs = this.arePrevStepRequiredInputsProvided();
            var toggleOff = (messageCount === 0) || !hasRequiredInitialInputs;
            wrapperDivSelector.toggleClass('off', toggleOff);
            // clear all the subarrays containing input controls for prior steps
            // TODO: as a future enhancement, we could keep track of which are already acknowledged
            // and keep them checked
            for (var _i = 0; _i < inputs.length; _i++) {
                var stepMsgInputs = inputs[_i];
                stepMsgInputs = [];
            }
            // remove all the inputs from the DOM
            contentDivSelector.empty();
            if ((!hasRequiredInitialInputs) || (!messageCount)) {
                return;
            }
            // if showing checkboxes to acknowledge messages, add a button to ak all of them after
            // a reasonable number
            var showAcknowledgeAllBtn = createCheckboxes && (messageCount >= 5);
            if (showAcknowledgeAllBtn) {
                this.addAcknowledgeAllButton(contentDivSelector);
            }
            var table = $('<table>').appendTo(contentDivSelector);
            // if we'll be adding checkboxes to the table, set headers to describe what they're for
            if (createCheckboxes) {
                var header = $('<thead>').appendTo(table);
                var headerCell = $('<th>').text('Warning').appendTo(header);
                headerCell = $('<th>').text('Acknowledge').appendTo(header);
            }
            var tableBody = $('<tbody>').appendTo(table)[0];
            userMessages.forEach(function (stepMessages, stepIndex) {
                stepMessages.forEach(function (message) {
                    var row = $('<tr>').appendTo(tableBody);
                    var cell = $('<td>').css('text-align', 'left').appendTo(row);
                    var div = $('<div>').attr('class', messageCssClass).appendTo(cell);
                    var span = $('<span class="warningStepLabel">').text("Step " + (stepIndex + 1)).appendTo(div);
                    var msgSpan = $('<span>').text(": " + message.message).appendTo(div);
                    if (!createCheckboxes) {
                        return;
                    }
                    var cell = $('<td>').css('text-align', 'center').toggleClass('errorMessage', !createCheckboxes).appendTo(row);
                    var checkbox = $('<input type="checkbox">').appendTo(cell);
                    _this.warningInputs[stepIndex].push(checkbox);
                    checkbox.on('click', null, {
                        'div': div,
                        'checkbox': checkbox
                    }, function (ev) {
                        var div = ev.data.div;
                        var checkbox = ev.data.checkbox;
                        _this.userSelectedWarningButton(div, checkbox);
                    });
                }, _this);
            });
            // if showing an 'Acknowledge All' button, repeat it at the bottom of the list
            if (showAcknowledgeAllBtn) {
                this.addAcknowledgeAllButton(contentDivSelector);
            }
        };
        ReviewStep.prototype.addAcknowledgeAllButton = function (contentDivSelector) {
            var button = $('<input type="button">')
                .addClass("acknowledgeAllButton")
                .val('Acknowledge  All')
                .click(this.userSelectedAcknowledgeAllButton.bind(this));
            button.appendTo(contentDivSelector);
        };
        ReviewStep.prototype.userSelectedWarningButton = function (div, checkbox) {
            // make the message text appear disabled (note it's purposefully distinct
            // from the checkbox to allow flexibility in expanding table contents)
            div.toggleClass('disabledTextLabel', checkbox.is(':checked'));
            //update the submit button
            this.updateSubmitEnabled();
        };
        ReviewStep.prototype.userSelectedAcknowledgeAllButton = function () {
            console.log('User selected ack all button'); // TODO: remove debug stmt
            // check whether all of the boxes are already checked
            var allSelected = true;
            for (var _i = 0, _a = this.warningInputs; _i < _a.length; _i++) {
                var stepCheckboxes = _a[_i];
                for (var _b = 0; _b < stepCheckboxes.length; _b++) {
                    var checkbox = stepCheckboxes[_b];
                    if (!checkbox.is(':checked')) {
                        allSelected = false;
                        break;
                    }
                }
            }
            // TODO: remove debug stmts
            if (allSelected) {
                console.log('All checkboxes already selected -- de-selecting.');
            }
            else {
                console.log('Not all checkboxes already selected -- selecting all');
            }
            // check or uncheck all of the boxes (some checked will result in all being checked)
            for (var _c = 0, _d = this.warningInputs; _c < _d.length; _c++) {
                var stepCheckboxes = _d[_c];
                for (var _e = 0; _e < stepCheckboxes.length; _e++) {
                    var checkbox = stepCheckboxes[_e];
                    checkbox.prop('checked', !allSelected);
                }
            }
            this.updateSubmitEnabled();
        };
        return ReviewStep;
    })();
    EDDTableImport.ReviewStep = ReviewStep;
})(EDDTableImport || (EDDTableImport = {}));
$(window).load(function () {
    EDDTableImport.onWindowLoad();
});
