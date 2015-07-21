// requires: jQuery, jQuery-UI
//
// XXX obtained from http://jsfiddle.net/alforno/g4stL/
// see copyright notice below
//
// TODO this is basically just a proof-of-concept - it is only used for the
// user field in a single view, but it has been confirmed to work with the
// (very crude) generic search function in edd.main.views.  A production
// version should use SOLR instead of Django to execute the search.
//

var EDD_auto = EDD_auto || {};
(function ($) { // immediately invoked function to bind jQuery to $

    var AutoColumn = function AutoColumn(name, width, valueField) {
        this.name = name;
        this.width = width;
        this.valueField = valueField;
        return this;
    };

    EDD_auto.cache_counter = EDD_auto.cache_counter || 0;
    // Static specification of column layout for each model in EDD that we want to
    // make searchable.  (This might be better done as a static JSON file
    // somewhere.)
    EDD_auto.column_layouts = $.extend(EDD_auto.column_layouts || {}, {
        "User" : [
            new AutoColumn('User', '150px', 'name'),
            new AutoColumn('Initials', '60px', 'initials'),
            new AutoColumn('E-mail', '120px', 'email')
            ],
        "Strain" : [
            new AutoColumn('Part ID', '100px', 'partId'),
            new AutoColumn('Name', '200px', 'name')
            ],
        "CarbonSource" : [
            new AutoColumn('Name', '150px', 'name'),
            new AutoColumn('Volume', '60px', 'volume'),
            new AutoColumn('Labeling', '100px', 'labeling'),
            new AutoColumn('Description', '150px', 'description'),
            new AutoColumn('Initials', '60px', 'initials')
            ]
    });
    EDD_auto.display_keys = $.extend(EDD_auto.display_keys || {}, {
        "User": 'name',
        "Strain": 'name',
        "CarbonSource": 'name'
    });
    EDD_auto.value_cache = $.extend(EDD_auto.value_cache || {}, {
        "User": 'Users',
        "Strain": 'Strains',
        "CarbonSource": 'CSources'
    })
    EDD_auto.value_keys = $.extend(EDD_auto.value_keys || {}, {
        "User": 'id',
        "Strain": 'recordId',
        "CarbonSource": 'id'
    });

/*
 * jQuery UI Multicolumn Autocomplete Widget Plugin 2.1
 * Copyright (c) 2012-2014 Mark Harmon
 *
 * Depends:
 * - jQuery UI Autocomplete widget
 *
 * Dual licensed under the MIT and GPL licenses:
 * http://www.opensource.org/licenses/mit-license.php
 * http://www.gnu.org/licenses/gpl.html
 */
$(window).load(function () {
    $.widget('custom.mcautocomplete', $.ui.autocomplete, {
        _create: function () {
            this._super();
            this.widget().menu("option", "items", "> :not(.ui-widget-header)");
        },
        _renderMenu: function (ul, items) {
            var self = this,
                thead;
            if (this.options.showHeader) {
                table = $('<div class="ui-widget-header" style="width:100%"></div>');
                $.each(this.options.columns, function (index, item) {
                    table.append('<span style="padding:0 4px;float:left;width:' + item.width + ';">' + item.name + '</span>');
                });
                table.append('<div style="clear: both;"></div>');
                ul.append(table);
            }
            $.each(items, function (index, item) {
                self._renderItem(ul, item);
            });
        },
        _renderItem: function (ul, item) {
            var t = '',
                result = '';
            $.each(this.options.columns, function (index, column) {
                t += '<span style="padding:0 4px;float:left;width:' + column.width + ';">' + item[column.valueField ? column.valueField : index] + '</span>'
            });
            result = $('<li></li>')
                .data('ui-autocomplete-item', item)
                .append('<a class="mcacAnchor">' + t + '<div style="clear: both;"></div></a>')
                .appendTo(ul);
            return result;
        }
    });

});


// Sets up the multicolumn autocomplete widget.  Must be called after the
// $(window).load handler above.
EDD_auto.setup_field_autocomplete = function setup_field_autocomplete(selector, model_name) {
    var empty = {}, columns, display_key, value_key, cache;
    if (typeof model_name === "undefined") {
        throw Error("model_name must be defined!");
    }
    columns = EDD_auto.column_layouts[model_name] || [ new AutoColumn('Name', '300px', 'name') ];
    display_key = EDD_auto.display_keys[model_name] || 'name';
    value_key = EDD_auto.value_keys[model_name] || 'id';
    cache = EDD_auto.value_cache[model_name] || ('cache_' + (++EDD_auto.cache_counter));
    EDDData[cache] = EDDData[cache] || {};
    empty[columns[0].valueField] = empty[0] = '<i>No Results Found</i>';
    columns.slice(1).forEach(function (column, index) {
        empty[column.valueField] = empty[index] = '';
    });
    // TODO add flag(s) to handle multiple inputs
    // TODO possibly also use something like https://github.com/xoxco/jQuery-Tags-Input
    $(selector).mcautocomplete({
        // These next two options are what this plugin adds to the autocomplete widget.
        // FIXME these will need to vary depending on record type
        showHeader: true,
        columns: columns,
        // Event handler for when a list item is selected.
        select: function (event, ui) {
            var cacheKey, record, display, value;
            if (ui.item) {
                cacheKey = ui.item[value_key];
                record = EDDData[cache][cacheKey] = EDDData[cache][cacheKey] || {};
                $.extend(record, ui.item);
                display = record[display_key] || '';
                value = record[value_key] || '';
                // assign value of selected item ID to sibling hidden input
                $(this).val(display).next('input[type=hidden]').val(value);
            }
            return false;
        },
    
        // The rest of the options are for configuring the ajax webservice call.
        minLength: 0,
        source: function (request, response) {
            $.ajax({
                // FIXME replace this with SOLR query
                url: '/search',
                dataType: 'json',
                data: {
                    model : model_name,
                    term : request.term
                },
                // The success event handler will display "No match found" if no items are returned.
                success: function (data) {
                    var result;
                    if (!data || !data.rows || data.rows.length === 0) {
                        result = [ empty ];
                    } else {
                        result = data.rows;
                    }
                    response(result);
                }
            });
        }
    }).on('blur', function (ev) {
        var hiddenId = $(this).next('input[type=hidden]').val(),
            old = EDDData[cache][hiddenId] || {};
        $(this).val(old[display_key] || '');
    });
};

/***********************************************************************/

$(window).load(function () {
    // add user autocomplete to all '.autocomp.autocomp_user' fields
    $('.autocomp.autocomp_user').each(function () {
        EDD_auto.setup_field_autocomplete(this, 'User', EDDData.Users);
    });
    $('.autocomp.autocomp_reg').each(function () {
        EDD_auto.setup_field_autocomplete(this, 'Strain', EDDData.Strains);
    });
    $('.autocomp.autocomp_carbon').each(function () {
        EDD_auto.setup_field_autocomplete(this, 'CarbonSource', EDDData.CSources);
    });
    $('.autocomp.autocomp_type').each(function () {
        EDD_auto.setup_field_autocomplete(this, 'MetadataType', EDDData.MetaDataTypes);
    })
});

}(jQuery));
