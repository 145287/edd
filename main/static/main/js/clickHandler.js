
//click handler for export modal
$(function(event) {
           var dlg = $("#line-popup").dialog({
               autoOpen: false
            });
            $("#line-export").click(function() {
               $("#line-popup").dialog( "open" );
                return false;
            });
     dlg.parent().appendTo('#line-action-form');
     return false;
         });


$(function(event) {
           var dlg = $("#assayMain").dialog({
               autoOpen: false
            });
            $("#addAssayToLine").click(function() {
               $("#assayMain").dialog( "open" );
                return false;
            });
     return false;
         });

//click handler for add measurements to selected assays modal
$(function(event) {
           var dlg = $("#addMeasToAssay").dialog({
               autoOpen: false
            });
            $("#measurementMain").click(function() {
               $("#addMeasToAssay").dialog( "open" );
                return false;
            });
     return false;
         });

//click handler for adding new line
$(function(event) {
           var dlg = $("#addNewLineForm").dialog({
               autoOpen: false
            });
            $("#addNewLine").click(function() {
               $("#addNewLineForm").dialog( "open" );
                return false;
            });
     return false;
         });

//click handler for filtering section
$(function(event) {
            $(".caret").click(function() {
               $("#mainFilterSection").slideDown(500);
                return false;
            });
        });


$(function() {
      //work around for generating worklist click handler
      $('#line_worklist').click(function() {
            $('select[name="export"]').val('worklist')
            var test = $('button[value="line_action"]')[1];
            $(test).click();
      });

      //show hide divs clicking lines button
      $('#linesTab').click(function (event) {
          event.preventDefault();
          $('#overviewTab').removeClass('active');
          $('#dataTab').removeClass('active');
          $(this).addClass('active');
          $('#dataDisplay').css('display', 'none');
          $('#measurementMain').css('display', 'none');
          $('.line-action').css('display', 'block');
         // $('#addNewLine').css('display', 'block'); hiding this for now until we figure out where to add it
      });

      //show hide divs clicking data button
      $('#dataTab').click(function (event) {
          event.preventDefault();
          $('#overviewTab').removeClass('active');
          $('#linesTab').removeClass('active');
          $(this).addClass('active');
          $('#dataDisplay').css('display', 'block');
          $('#measurementMain').css('display', 'inline-block');
          $('.line-action').css('display', 'none');
          //$('#addNewLine').css('display', 'none') see above
      });

      //show hide for clicking graph tab under data
      $('#studyGraph').click(function (event) {
          event.preventDefault();
          // $('#assaysSection').prev().hide()
          $('#studyTable').removeClass('active');
          $(this).addClass('active');
          $('#overviewSection').css('display', 'block');
          $('#assaysSection').css('display', 'none');
          return false
      });

      //show hide for clicking table tab under data
      $('#studyTable').click(function (event) {
          event.preventDefault();
          StudyD.assaysDataGrids.triggerAssayRecordsRefresh();
          // $('#assaysSection').prev().show();
          $('#studyGraph').removeClass('active');
          $(this).addClass('active');
          $('#assaysSection').css('display', 'block');
          $('#overviewSection').css('display', 'none');
          return false
      });
  });