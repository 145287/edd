/// <reference path="typescript-declarations.d.ts" />
/// <reference path="Utl.ts" />
/// <reference path="Dragboxes.ts" />
/// <reference path="DataGrid.ts" />
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
};
var StudyOverview;
(function (StudyOverview) {
    'use strict';
    var attachmentIDs;
    var attachmentsByID;
    var prevDescriptionEditElement;
    var activeDraggedFile;
    var fileUploadProgressBar;
    // Called when the page loads.
    function prepareIt() {
        this.attachmentIDs = null;
        this.attachmentsByID = null;
        this.prevDescriptionEditElement = null;
        this.metabolicMapID = -1;
        this.metabolicMapName = null;
        this.biomassCalculation = -1;
        new EditableStudyContact($('#editable-study-contact').get()[0]);
        new EditableStudyDescription($('#editable-study-description').get()[0]);
        // put the click handler at the document level, then filter to any link inside a .disclose
        $(document).on('click', '.disclose .discloseLink', function (e) {
            $(e.target).closest('.disclose').toggleClass('discloseHide');
            return false;
        });
        $('#helpExperimentDescription').tooltip({
            content: function () {
                return $(this).prop('title');
            },
            position: { my: "left-10 center", at: "right center" },
            show: null,
            close: function (event, ui) {
                ui.tooltip.hover(function () {
                    $(this).stop(true).fadeTo(400, 1);
                }, function () {
                    $(this).fadeOut("400", function () {
                        $(this).remove();
                    });
                });
            }
        });
        this.fileUploadProgressBar = new Utl.ProgressBar('fileUploadProgressBar');
        Utl.FileDropZone.create({
            elementId: "templateDropZone",
            fileInitFn: this.fileDropped.bind(this),
            processRawFn: this.fileRead.bind(this),
            url: '/study/' + EDDData.currentStudyID + '/describe/',
            processResponseFn: this.fileReturnedFromServer.bind(this),
            processErrorFn: this.fileErrorReturnedFromServer.bind(this),
            progressBar: this.fileUploadProgressBar
        });
        Utl.Tabs.prepareTabs();
        $(window).on('load', preparePermissions);
    }
    StudyOverview.prepareIt = prepareIt;
    // This is called upon receiving a response from a file upload operation, and unlike
    // fileRead(), is passed a processed result from the server as a second argument,
    // rather than the raw contents of the file.
    function fileReturnedFromServer(fileContainer, result) {
        var currentPath = window.location.pathname;
        var linesPathName = currentPath.slice(0, currentPath.lastIndexOf('overview')) + 'experiment-description';
        //display success message
        $('<p>', {
            text: 'Success! ' + result['lines_created'] + ' lines added!',
            style: 'margin:auto'
        }).appendTo('#linesAdded');
        $('#linesAdded').show();
        //redirect to lines page
        setTimeout(function () {
            window.location.pathname = linesPathName;
        }, 1000);
    }
    StudyOverview.fileReturnedFromServer = fileReturnedFromServer;
    // This is called upon receiving an errror in a file upload operation, and
    // is passed an unprocessed result from the server as a second argument.
    function fileErrorReturnedFromServer(fileContainer, response, url) {
        // reset the drop zone here
        //parse xhr.response
        var obj, error, warning, errorMessage, warnings, id;
        try {
            obj = JSON.parse(response);
            if (obj['errors']) {
                generateErrors(obj['errors']);
            }
            if (obj['warnings']) {
                generateWarnings(obj['warnings']);
            }
        }
        catch (e) {
            alertError("", "There was an error. EDD administrators have been notified. Please try again later.");
        }
        //if there is more than one alert, add a dismiss all alerts button
        if ($('.alert').length > 2) {
            $('#alert_placeholder').prepend('<a href="" class="dismissAll" id="dismissAll">Dismiss all alerts</a>');
        }
        //set up click handler events
        $('#omitStrains').change(function () {
            var f = fileContainer.file;
            fileContainer.extraHeaders['ignoreIceRelatedErrors'] = 'true';
            f.sendTo(window.location.pathname.split('overview')[0] + 'describe/');
        });
        $('#allowDuplicates').change(function () {
            var f = fileContainer.file;
            fileContainer.extraHeaders['ALLOWDUPLICATENAMES'] = 'true';
            f.sendTo(window.location.pathname.split('overview')[0] + 'describe/');
        });
        $('#noDuplicates').change(function () {
            window.location.reload();
        });
        //dismiss all alerts on click
        $('#dismissAll').on('click', function () {
            $('.close').click();
            $('#dismissAll').remove();
        });
    }
    StudyOverview.fileErrorReturnedFromServer = fileErrorReturnedFromServer;
    function generateWarnings(warnings) {
        for (var key in warnings) {
            alertWarning(key, warnings[key]);
        }
    }
    function generateErrors(errors) {
        for (var key in errors) {
            if (key === "ICE-related error") {
                // create dismissible error alert
                alertError('', key);
                alertICEError(key, errors[key]);
            }
            else if (key === "Duplicate assay names in the input" || key === "Duplicate line names in the input") {
                if ($('#duplicateError').length === 0) {
                    alertDuplicateError(key, errors[key]);
                }
            }
            else {
                alertError(key, errors[key]);
            }
        }
    }
    function alertICEError(subject, message) {
        $('#alert_placeholder').append('<div id="iceError" class="alert alert-warning alert-dismissible"><button type="button" ' +
            'class="close" data-dismiss="alert">&times;</button><span class="alertSubject">' + subject +
            '</span> ' + message + '</div>');
        $('#iceError').append('<span class="allowError">Omit Strains?</span>' +
            '<input type="radio" style="margin-right:10px" id="omitStrains">Yes</input>' +
            '<input type="radio" class="dontAllowError" id="noDuplicates">No</input>');
    }
    function alertDuplicateError(subject, message) {
        $('#alert_placeholder').append('<div id="duplicateError" class="alert alert-warning alert-dismissible"><button type="button" ' +
            'class="close" data-dismiss="alert">&times;</button><span class="alertSubject">' + subject + '</span>' +
            '<span> ' + message + '</span></div>');
        $('#duplicateError').append('<span class="allowError">Allow Duplicates?</span>' +
            '<input type="radio" style="margin-right:10px" id="allowDuplicates">Yes</input>' +
            '<input type="radio" class="dontAllowError" id="noDuplicates">No</input>');
    }
    function alertError(subject, message) {
        $('#alert_placeholder').append('<div class="alert alert-danger alert-dismissible"><button type="button" ' +
            'class="close" data-dismiss="alert">&times;</button><span class="alertSubject">Error uploading! ' + subject +
            '</span><span> : ' + message + '</span></div>');
        clearDropZone();
    }
    function alertWarning(subject, message) {
        $('#alert_placeholder').append('<div class="alert alert-warning alert-dismissible"><button type="button" ' +
            'class="close" data-dismiss="alert">&times;</button><span class="alertSubject">' + subject +
            '</span><span> : ' + message + '</span></div>');
    }
    function clearDropZone() {
        $('#templateDropZone').removeClass('off');
        $('#fileDropInfoIcon').addClass('off');
        $('#fileDropInfoName').addClass('off');
        $('#fileDropInfoSending').addClass('off');
    }
    // Here, we take a look at the type of the dropped file and decide whether to
    // send it to the server, or process it locally.
    // We inform the FileDropZone of our decision by setting flags in the fileContainer object,
    // which will be inspected when this function returns.
    function fileDropped(fileContainer, iceError) {
        this.haveInputData = true;
        //processingFileCallback();
        var ft = fileContainer.fileType;
        // We'll signal the dropzone to upload this, and receive processed results.
        if (ft === 'xlsx') {
            fileContainer.skipProcessRaw = true;
            fileContainer.skipUpload = false;
        }
        // HPLC reports need to be sent for server-side processing
        if (!fileContainer.skipProcessRaw || !fileContainer.skipUpload) {
            this.showFileDropped(fileContainer, iceError);
        }
    }
    StudyOverview.fileDropped = fileDropped;
    // Reset and show the info box that appears when a file is dropped,
    // and reveal the text entry area.
    function showFileDropped(fileContainer) {
        var processingMessage = '';
        // Set the icon image properly
        $('#fileDropInfoIcon').removeClass('xml');
        $('#fileDropInfoIcon').removeClass('text');
        $('#fileDropInfoIcon').removeClass('excel');
        if (fileContainer.fileType === 'xml') {
            $('#fileDropInfoIcon').addClass('xml');
        }
        else if (fileContainer.fileType === 'xlsx') {
            $('#fileDropInfoIcon').addClass('excel');
        }
        else if (fileContainer.fileType === 'plaintext') {
            $('#fileDropInfoIcon').addClass('text');
        }
        $('#templateDropZone').addClass('off');
        $('#fileDropInfoArea').removeClass('off');
        $('#fileDropInfoSending').removeClass('off');
        $('#fileDropInfoName').text(fileContainer.file.name);
        if (!fileContainer.skipUpload) {
            processingMessage = 'Sending ' + Utl.JS.sizeToString(fileContainer.file.size) + ' To Server...';
            $('#fileDropInfoLog').empty();
        }
        else if (!fileContainer.skipProcessRaw) {
            processingMessage = 'Processing ' + Utl.JS.sizeToString(fileContainer.file.size) + '...';
            $('#fileDropInfoLog').empty();
        }
        $('#fileUploadMessage').text(processingMessage);
        this.activeDraggedFile = fileContainer;
    }
    StudyOverview.showFileDropped = showFileDropped;
    // This function is passed the usual fileContainer object, but also a reference to the
    // full content of the dropped file.
    function fileRead(fileContainer, result) {
        this.haveInputData = true;
    }
    StudyOverview.fileRead = fileRead;
    function preparePermissions() {
        var user, group;
        user = new EDDAuto.User({
            container: $('#permission_user_box')
        });
        group = new EDDAuto.Group({
            container: $('#permission_group_box')
        });
        //check public permission input on click
        $('#set_everyone_permission').on('click', function () {
            $('#permission_public').prop('checked', true);
        });
        $('#set_group_permission').on('click', function () {
            $('#permission_group').prop('checked', true);
        });
        $('#set_user_permission').on('click', function () {
            $('#permission_user').prop('checked', true);
        });
        $('form#permissions')
            .on('submit', function (ev) {
            var perm = {}, klass, auto;
            auto = $('form#permissions').find('[name=class]:checked');
            klass = auto.val();
            perm.type = $(auto).siblings('select').val();
            perm[klass.toLowerCase()] = { 'id': $(auto).siblings('input:hidden').val() };
            $.ajax({
                'url': '/study/' + EDDData.currentStudyID + '/permissions/',
                'type': 'POST',
                'data': {
                    'data': JSON.stringify([perm]),
                    'csrfmiddlewaretoken': $('form#permissions').find('[name=csrfmiddlewaretoken]').val()
                },
                'success': function () {
                    var permissionTarget;
                    console.log(['Set permission: ', JSON.stringify(perm)].join(''));
                    //reset permission options
                    $('form#permissions').find('.autocomp_search').siblings('select').val('N');
                    //reset input
                    $('form#permissions').find('.autocomp_search').val('');
                    $('<div>').text('Permission Updated').addClass('success')
                        .appendTo($('form#permissions')).delay(2000).fadeOut(2000);
                },
                'error': function (xhr, status, err) {
                    console.log(['Setting permission failed: ', status, ';', err].join(''));
                    //reset permission options
                    $('form#permissions').find('.autocomp_search').siblings('select').val('N');
                    //reset input
                    $('form#permissions').find('.autocomp_search').val('');
                    $('<div>').text('Server Error: ' + err).addClass('bad')
                        .appendTo($('form#permissions')).delay(5000).fadeOut(2000);
                }
            });
            return false;
        })
            .find(':radio').trigger('change').end()
            .removeClass('off');
        //set style on inputs for permissions
        $('#permission_user_box').find('input').insertBefore('#user_permission_options').addClass('permissionUser');
        $('#permission_group_box').find('input').insertBefore('#group_permission_options').addClass('permissionGroup');
        $('#permission_public_box').addClass('permissionGroup');
        // Set up the Add Measurement to Assay modal
        $("#permissionsSection").dialog({
            minWidth: 500,
            autoOpen: false
        });
        $("#addPermission").click(function () {
            $("#permissionsSection").removeClass('off').dialog("open");
            return false;
        });
        //TODO: remove this and fix bug
        $("#attachmentsSection a:contains('Delete')").hide();
    }
    function onChangedMetabolicMap() {
        if (this.metabolicMapName) {
            // Update the UI to show the new filename for the metabolic map.
            $("#metabolicMapName").html(this.metabolicMapName);
        }
        else {
            $("#metabolicMapName").html('(none)');
        }
    }
    StudyOverview.onChangedMetabolicMap = onChangedMetabolicMap;
    // They want to select a different metabolic map.
    function onClickedMetabolicMapName() {
        var _this = this;
        var ui, callback = function (error, metabolicMapID, metabolicMapName, finalBiomass) {
            if (!error) {
                _this.metabolicMapID = metabolicMapID;
                _this.metabolicMapName = metabolicMapName;
                _this.biomassCalculation = finalBiomass;
                _this.onChangedMetabolicMap();
            }
            else {
                console.log("onClickedMetabolicMapName error: " + error);
            }
        };
        ui = new StudyMetabolicMapChooser(false, callback);
    }
    StudyOverview.onClickedMetabolicMapName = onClickedMetabolicMapName;
    var EditableStudyDescription = (function (_super) {
        __extends(EditableStudyDescription, _super);
        function EditableStudyDescription(inputElement) {
            _super.call(this, inputElement);
            this.minimumRows = 4;
        }
        EditableStudyDescription.prototype.getFormURL = function () {
            return '/study/' + EDDData.currentStudyID + '/setdescription/';
        };
        EditableStudyDescription.prototype.getValue = function () {
            return EDDData.Studies[EDDData.currentStudyID].description;
        };
        EditableStudyDescription.prototype.setValue = function (value) {
            EDDData.Studies[EDDData.currentStudyID].description = value;
        };
        EditableStudyDescription.prototype.blankLabel = function () {
            return '(click to add description)';
        };
        return EditableStudyDescription;
    }(StudyBase.EditableStudyElement));
    StudyOverview.EditableStudyDescription = EditableStudyDescription;
    var EditableStudyContact = (function (_super) {
        __extends(EditableStudyContact, _super);
        function EditableStudyContact() {
            _super.apply(this, arguments);
        }
        // Have to reproduce these here rather than using EditableStudyElement because the inheritance is different
        EditableStudyContact.prototype.editAllowed = function () { return EDDData.currentStudyWritable; };
        EditableStudyContact.prototype.canCommit = function (value) { return EDDData.currentStudyWritable; };
        EditableStudyContact.prototype.getFormURL = function () {
            return '/study/' + EDDData.currentStudyID + '/setcontact/';
        };
        EditableStudyContact.prototype.getValue = function () {
            return EDDData.Studies[EDDData.currentStudyID].contact;
        };
        EditableStudyContact.prototype.setValue = function (value) {
            EDDData.Studies[EDDData.currentStudyID].contact = value;
        };
        return EditableStudyContact;
    }(EDDEditable.EditableAutocomplete));
    StudyOverview.EditableStudyContact = EditableStudyContact;
})(StudyOverview || (StudyOverview = {}));
;
// use JQuery ready event shortcut to call prepareIt when page is ready
$(function () { return StudyOverview.prepareIt(); });
