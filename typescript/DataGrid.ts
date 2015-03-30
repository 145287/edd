/// <reference path="typescript-declarations.d.ts" />
/// <reference path="Utl.ts" />
/// <reference path="Dragboxes.ts" />
/// <reference path="lib/jquery.d.ts" />

//
// This is a re-implementation of DataGridServerSide for wholly client-side tables.
// Eventually DataGridServerSide should be phased out completely.
//

class DataGrid {

	// This binds a table element to an instance of DataGrid.
	// The previous contents of the table, if any, are deleted, and DataGrid takes over the table
	constructor(dataGridSpec:DataGridSpecBase) {

        // Use !! double-not operator to coerce truth-y/false-y values to booleans
		Utl.JS.assert(!!dataGridSpec, "DataGrid needs to be supplied with a DataGridSpecBase-derived object.");
		Utl.JS.assert(
			!!(dataGridSpec.tableElement && dataGridSpec.tableSpec && dataGridSpec.tableHeaderSpec &&
			dataGridSpec.tableColumnSpec),
			"DataGridSpecBase-derived object does not have enough to work with.");

		//
		// Member variable declarations
		//

		// We need a DataGridSpecBase-derived table specification.
		// (This object describes the table and implements custom functionality
		// that belongs with whoever created the table.)
		// (See the DataGridSpecBase class to see what can be implemented.)
		this._spec = dataGridSpec;
		this._table = dataGridSpec.tableElement;
		this._timers = {};

		var tableBody = $(this._tableBody = document.createElement("tbody"));

		// First step: Blow away the old contents of the table
        $(this._table).empty()
            .attr({ 'cellpadding': 0, 'cellspacing': 0 })
            .addClass('dataTable sortable dragboxes hastablecontrols')  // TODO: Most of these classes are probably not needed now
            .append(tableBody);

		var tableHeaderRow = $(document.createElement("tr")).addClass('header');
        var tableHeaderCell = $(this._tableHeaderCell = document.createElement("th"))
            .appendTo(tableHeaderRow);
		if (dataGridSpec.tableSpec.name) {
			$(this.tableTitleSpan = document.createElement("span")).text(dataGridSpec.tableSpec.name).appendTo(tableHeaderCell);
		}
        var waitBadge = $(this._waitBadge = document.createElement("span"))
            .addClass('waitbadge wait').appendTo(tableHeaderCell);
		if ((this._totalColumnCount = this.countTotalColumns()) > 1) {
            tableHeaderCell.attr('colspan', this._totalColumnCount);
		}

		// If we're asked to show the header, then add it to the table.  Otherwise we will leave it off.
		if (dataGridSpec.tableSpec.showHeader) {
			tableBody.append(tableHeaderRow);
		}

		// Apply the default column visibility settings.
		// TODO: Read in the user-defined column visibility hash and apply it before first rendering the table
		this.prepareColumnVisibility(null);

        var headerRows = this._headerRows = this._buildTableHeaders();
        this._headerRows.forEach((v) => tableBody.append(v));

		setTimeout( () => this._initializeTableData(), 1 );
	}


	// Breaking up the initial table creation into two stages allows the browser to render a preliminary
	// version of the table with a header but no data rows, then continue loading other assets in parallel.
	// It actually speeds up the entire table creation as well, for reasons that are not very clear.
	// (If the setup is NOT run in two stages, all the 'createElement' calls for the data cells take much longer,
	// in Firefox and Safari, according to load-time profiling ... and only when paired with some servers??)
	_initializeTableData():DataGrid {

		var hCell = this._tableHeaderCell;

		this._buildAllTableSorters()
            ._buildTableSortSequences()
            ._allocateTableRowRecords()
            ._buildRowGroupTitleRows()
            ._createOptionsMenu()
            ._createHeaderWidgets();

		// First, append the header widgets that should to appear "after" the pulldown.
		// (Since all widgets are styled to float right, they will appear from right to left.)
        this._headerWidgets.forEach((widget, index) => {
			if (!widget.displayBeforeViewMenu()) {
				widget.appendElements(hCell, index.toString(10));
			}
		});
		// Now append the 'View' pulldown menu
		hCell.appendChild(this._optionsMenuElement);
		// Finally, append the header widgets that should appear "before".
        this._headerWidgets.forEach((widget, index) => {
			if (widget.displayBeforeViewMenu()) {
				widget.appendElements(hCell, index.toString(10));
			}
		});

        this._sortHeaderCurrent = this._spec.tableHeaderSpec[this._spec.tableSpec.defaultSort || 0];
		this.arrangeTableDataRows();

		// Now that we've constructed our elements, apply visibility styling to them.
		this._applyColumnVisibility();

    	// Prepare the table for sorting
   		this._prepareSortable();

		this._spec.onInitialized(this);
		$(this._waitBadge).addClass('off');

        return this;
	}


    // Notify the DataGrid that its underlying data has reset
    triggerDataReset():DataGrid {
        // We have new data to display. Clear out old rows.
        $.each(this._recordElements, (index:number, value:DataGridRecord) => {
            value.removeElements();
        });
        this._spec.onDataReset(this);
        // Rebuild rows.
        this._buildTableSortSequences()._allocateTableRowRecords()
        // And then arrange the rows
            .arrangeTableDataRows();

		// Call the support function in each widget, to apply styling to all the data rows of the table.
        this._optionsMenuWidgets.forEach((widget) => {
            this._spec.getRecordIDs().forEach((id) => {
				widget.initialFormatRowElementsForID(this._recordElements[id].getDataGridDataRows(), id);
			});
		});

        this._headerWidgets.forEach((widget) => {
            this._spec.getRecordIDs().forEach((id) => {
				widget.initialFormatRowElementsForID(this._recordElements[id].getDataGridDataRows(), id);
			});
		});

        // And make sure only the currently visible things are ... visible
        this._applyColumnVisibility();
        this._headerWidgets.forEach((widget, index) => {
            widget.refreshWidget();
        });
        this._optionsMenuWidgets.forEach((widget, index) => {
            widget.refreshWidget();
        });
        return this;
    }


    // Update only the table rows for the specified records.
    // For use in situations where you want to add rows, or rebuild existing rows,
    // and leave the rest unchanged.
    triggerPartialDataReset(recordIDs:number[], reflow:boolean):DataGrid {
        this._spec.onPartialDataReset(this, recordIDs);
        // Rebuild rows.
        recordIDs.forEach((id) => {
        	this.reconstructSingleRecord(id);
        });

        if (reflow) {
	        this._buildTableSortSequences().arrangeTableDataRows();

	        this._headerWidgets.forEach((widget, index) => {
	            widget.refreshWidget();
	        });
	        this._optionsMenuWidgets.forEach((widget, index) => {
	            widget.refreshWidget();
	        });
	    }
        return this;
    }


    // Instruct DataGrid to recreate/refresh everything related to a single record ID.
    // This includes removing its table rows, reconstructing them, reformatting them, and
    // re-adding the rows in the same place as the old, but does NOT rebuild the sort sequences.
    //   NOTE:
    // It's quite possible that changes to the appearance will alter the visibility of the rows in
    // complicated ways.  For example, the generic search widget logic may decide to hide a previously shown
    // row or vice-versa, corrupting row striping.  Do not delay the reflow for too long.
    reconstructSingleRecord(recordID:number):DataGrid {
        if (this._recordElements[recordID]) {
            this._recordElements[recordID].reCreateElementsInPlace();
        } else {
	    	// Note that if the record didn't exist before, it will not appear in the table now,
    		// until a complete reflow is done by rebuilding sort sequences and calling arrangeTableDataRows.
            this._recordElements[recordID] = new DataGridRecord(this._spec, recordID);
        }

        var dgRecord = this._recordElements[recordID];

		// Call the support function in each widget, to apply styling to all the data rows of the table.
        this._optionsMenuWidgets.forEach((widget) => {
			widget.initialFormatRowElementsForID(dgRecord.getDataGridDataRows(), recordID);
		});

        this._headerWidgets.forEach((widget) => {
			widget.initialFormatRowElementsForID(dgRecord.getDataGridDataRows(), recordID);
		});

        // Make sure only the currently visible things are ... visible
        this._applyColumnVisibilityToOneRecord(recordID);
        return this;
    }


	private _createOptionsMenu():DataGrid {
		var mainID = this._spec.tableSpec.id;

		// Populate the master list of custom options menu widgets by calling the initialization routine in the spec
		this._optionsMenuWidgets = this._spec.createCustomOptionsWidgets(this);
		var hasCustomWidgets:boolean = this._optionsMenuWidgets.length > 0;

		// Check in the column groups and see if any are hide-able
		var hasColumnsInVisibilityList:boolean = this._spec.tableColumnGroupSpec.some((group) => {
            return group.showInVisibilityList;
        });

		// If none of the groups are allowed to be hidden, and we don't have any custom option widgets,
		// don't bother creating the column visibility menu
		if (!hasColumnsInVisibilityList && !hasCustomWidgets) {
			return;
		}

		// If we have custom widgets, we need to call their support functions that apply styling
		// to all the data rows of the table.
		if (hasCustomWidgets) {
            this._optionsMenuWidgets.forEach((widget) => {
                this._spec.getRecordIDs().forEach((id) => {
					widget.initialFormatRowElementsForID(this._recordElements[id].getDataGridDataRows(), id);
				});
			});
		}

		var mainSpan = $(this._optionsMenuElement = document.createElement("span"))
            .attr('id', mainID + 'ColumnChooser').addClass('pulldownMenu');

		var menuLabelOn = $(this._optionsLabelOnElement = document.createElement("div"))
            .addClass('pulldownMenuLabelOn off')    // Hidden with 'off' until we need it
            .text('View\u25BE').click(() => this._clickedOptMenuWhileOn()).appendTo(mainSpan);
		var menuLabelOff = $(this._optionsLabelOffElement = document.createElement("div"))
            .addClass('pulldownMenuLabelOff').text('View\u25BE')
            .click(() => this._clickedOptMenuWhileOff()).appendTo(mainSpan);

		var menuBlock = $(this._optionsMenuBlockElement = document.createElement("div"))
            .addClass('pulldownMenuMenuBlock off').appendTo(mainSpan);

		if (hasCustomWidgets) {
			var menuCWList = $(document.createElement("ul")).appendTo(menuBlock);
			if (hasColumnsInVisibilityList) {
                menuCWList.addClass('withDivider');
			}
            this._optionsMenuWidgets.forEach((widget, index) => {
				widget.appendElements($(document.createElement("li")).appendTo(menuCWList)[0], index.toString(10));
			});
		}

		if (hasColumnsInVisibilityList) {
			var menuColList = $(document.createElement("ul")).appendTo(menuBlock);
			// Add each hide-able group to the menu.
			// Note: We have to walk through this anew, because we're going to make use of the index 'i'.
            this._spec.tableColumnGroupSpec.forEach((group, index) => {
                if (!group.showInVisibilityList) {
                    return;
                }
				var item = $(document.createElement("li")).appendTo(menuColList);
                var id:string = mainID + 'ColumnCheckbox' + (index + 1);
				var checkbox = $(group.checkboxElement = document.createElement("input"))
                    .appendTo(item).attr({ 'id': id, 'name': id, 'value': index + 1 })
                    .click((e) => this._clickedColVisibilityControl(e));
                group.checkboxElement.type = 'checkbox'; // cannot set this via jQuery
				if (!group.currentlyHidden) {
                    checkbox.prop('checked', true);
				}
				$(document.createElement("label")).appendTo(item).attr('for', id).text(group.name);
			});
		}

        return this;
	}


	private _createHeaderWidgets():DataGrid {
		// Populate the master list of custom header widgets by calling the initialization routine in the spec
		this._headerWidgets = this._spec.createCustomHeaderWidgets(this);
        this._headerWidgets.forEach((widget) => {
			// Call the support function in each widget, to apply styling to all the data rows of the table.
            this._spec.getRecordIDs().forEach((id) => {
				widget.initialFormatRowElementsForID(this._recordElements[id].getDataGridDataRows(), id);
			});
		});
        return this;
	}


	// Prepare the column visibility state for the table.
	// If given a flagHash object, look in the object for attributes matching the column group IDs,
	// and enable or disable the column groups accordingly.
	// This function should be called during instantiation, since it initializes the column visibility
	// variables that are referred to throughout the rest of the DataGrid class.
	// TODO: Call the 'made visible' spec callback for any columns that are initially visible
	prepareColumnVisibility(flagHash:{}) {
		// First, run through a sequence of checks to set the 'currentlyHidden' attribute to a reasonable value.
        this._spec.tableColumnGroupSpec.forEach((group, index) => {
			// Establish what the default is, before checking any passed-in column flags
			group.currentlyHidden = !!group.hiddenByDefault;
			if (flagHash) {
				// Column groups are numbered starting from 1, so when we prepare the 0th group,
				// we need to check in the hash for the attribute 1.
                group.currentlyHidden = !flagHash[index + 1];
			}
            // Ensure that the necessary arrays are present to keep track of group members
            group.memberHeaders = group.memberHeaders || [];
            group.memberColumns = group.memberColumns || [];
		});

		// Collect all the headers under their respective column groups
        this._spec.tableHeaderSpec.forEach((header) => {
            var c = header.columnGroup;
            if (c && this._spec.tableColumnGroupSpec[c - 1]) {
                this._spec.tableColumnGroupSpec[c - 1].memberHeaders.push(header);
            }
		});

		// Collect all the columns (and in turn their cells) under their respective column groups
        this._spec.tableColumnSpec.forEach((col) => {
            var c = col.columnGroup;
            if (c && this._spec.tableColumnGroupSpec[c - 1]) {
                this._spec.tableColumnGroupSpec[c - 1].memberColumns.push(col);
            }
		});
	}


	// Read the current column visibility state and alter the styling of headers and cells to reflect it

	private _applyColumnVisibility():DataGrid {
        this._spec.tableColumnGroupSpec.forEach((group) => {
            var hidden = group.currentlyHidden;

            group.memberHeaders.forEach((header) => $(header.element).toggleClass('off', hidden));

            group.memberColumns.forEach((column) => {
				column.getEntireIndex().forEach((c) => hidden ? c.hide() : c.unhide());
			});
		});
        return this;
	}


	private _applyColumnVisibilityToOneRecord(recordID:number):DataGrid {
        this._spec.tableColumnGroupSpec.forEach((group) => {
            var hidden = group.currentlyHidden;
            group.memberColumns.forEach((column) => {
				column.cellIndexAtID(recordID).forEach((c) => hidden ? c.hide() : c.unhide());
			});
		});
        return this;
	}


	// Return a copy of the array of DataGridDataCell objects, for the column at the given index in the spec.
	getDataCellObjectsForColumnIndex(i:number):DataGridDataCell[] {
        if (this._spec.tableColumnSpec[i]) {
            return this._spec.tableColumnSpec[i].getEntireIndex();
        }
        return [];
	}


	// Get the list of IDs, then filter it down to what's visible,
	// then search the visible rows for spec-mandated checkbox elements,
	// and if a checkbox is checked, return its element on an array.
	getSelectedCheckboxElements():HTMLInputElement[] {
		var sequence:number[] = this._sortHeaderCurrent.sortSequence;

        // Verify that the row sets referred to by the IDs actually exist
		var filteredSequence = sequence.filter((v) => { return !!this._recordElements[v]; });

		filteredSequence = this.applyAllWidgetFiltering(filteredSequence);

		var checkedBoxes:HTMLInputElement[] = [];
        filteredSequence.forEach((v) => {
            var rows = this._recordElements[v].getDataGridDataRows();
            rows.forEach((row) => {
                if (!row.dataGridDataCells) {
                    return;
                }
                row.dataGridDataCells.forEach((cell) => {
                    var checkbox = cell.getCheckboxElement();
                    if (checkbox && checkbox.checked) {
                        checkedBoxes.push(checkbox);
                    }
                });
            });
        });
		return checkedBoxes;
	}


	arrangeTableDataRows() {
		var currentSortHeader:DataGridHeaderSpec = this._sortHeaderCurrent;
		var striping = 1;

		// We create a document fragment - a kind of container for document-related objects that we don't
		// want in the page - and accumulate inside it all the rows we want to display, in sorted order.
		var frag = document.createDocumentFragment();

        // We need to track which header was the last to sort this table,
        // If that reference is null, the table is being displayed sorted for the first time.
		var lastSorted:DataGridHeaderSpec = this._sortHeaderPrevious === null ?
            this._sortHeaderCurrent :
            this._sortHeaderPrevious;
		$(lastSorted.element).removeClass('sortedup sorteddown');

		var isReversed:boolean = currentSortHeader.sortCurrentlyReversed;
		// Update CSS styles to reflect which direction it's sorted in.
		$(currentSortHeader.element).removeClass('sortwait').addClass(isReversed ? 'sorteddown' : 'sortedup');

        // If we're in reversed mode, use the reversed version of the sort sequence
		var sequence = isReversed ? currentSortHeader.sortSequenceReversed : currentSortHeader.sortSequence;

        // Verify that the row sets referred to by the IDs actually exist
		var filteredSequence = sequence.filter((v) => { return !!this._recordElements[v]; });
        var unfilteredSequence = filteredSequence.slice(0);

		// Remove all the grouping title rows from the table as well, if they were there
		var rowGroupSpec = this._spec.tableRowGroupSpec;
        rowGroupSpec.forEach((rowGroup) => {
            var r = rowGroup.disclosedTitleRow;
            if (r.parentNode) { // As with regular rows, we're assuming the row is a child only of this table body.
                this._tableBody.removeChild(r);
            }
            r = rowGroup.undisclosedTitleRow;
            if (r.parentNode) { // As with regular rows, we're assuming the row is a child only of this table body.
                this._tableBody.removeChild(r);
            }
            // While we're here, reset the member record arrays.  We need to rebuild them post-filtering.
            rowGroup.memberRecords = [];
        });

		filteredSequence = this.applyAllWidgetFiltering(filteredSequence);

		// Call to detach only the rows that didn't make it through the filter.
		// The others will be automatically detached by being moved to the document fragment.
		var addedRowIDs = {};
		filteredSequence.forEach((id) => {
			addedRowIDs[id] = true;
		});
        unfilteredSequence.forEach((id) => {
			if (!addedRowIDs[id]) {
				this._recordElements[id].detachElements();
			}
		});

		// Now we run through the remaining IDs and add their rows to the table, with striping.
		// But if grouping is enabled and there is at least one group, we add them a few at a time,
		// proceeding through each group.

		if (!this._groupingEnabled || rowGroupSpec.length < 1) {	// The standard non-grouped method:

			if (this._spec.tableSpec.applyStriping) {
    			filteredSequence.forEach((s) => {
					striping = 1 - striping;
					this._recordElements[s].applyStriping(striping);
				});
        	}
            filteredSequence.forEach((s) => {
                var rows = this._recordElements[s].getElements();
                rows.forEach((row) => {
					frag.appendChild(row);
				});
			});

		} else {	// The more complicated, grouped method:

			var stripeStyles = ['stripeRowA','stripeRowB'];
	        var stripeStylesJoin = stripeStyles.join(' ');

			filteredSequence.forEach((s) => {
				var rowGroup = rowGroupSpec[this._spec.getRowGroupMembership(s)];
               	rowGroup.memberRecords.push(this._recordElements[s]);
			});

		 	rowGroupSpec.forEach((rowGroup) => {
				if (rowGroup.memberRecords.length < 1) {
					// If there's nothing in the group (may have all been filtered out) skip it
					return;
				}
				striping = 1 - striping;
				if (this._spec.tableSpec.applyStriping) {
                    rowGroup.undisclosedTitleRowJQ.add(rowGroup.disclosedTitleRowJQ)
                        .removeClass(stripeStylesJoin).addClass(stripeStyles[striping]).end();
				}
				if (!rowGroup.disclosed) {
					// If the group is not disclosed, just print the "undisclosed" title row, and skip the
					// rows themselves (but invert the striping value so the striping pattern isn't disturbed)
					frag.appendChild(rowGroup.undisclosedTitleRow);
					return;
				}
				frag.appendChild(rowGroup.disclosedTitleRow);

			 	rowGroup.memberRecords.forEach((record) => {
					striping = 1 - striping;
					if (this._spec.tableSpec.applyStriping) {
						record.applyStriping(striping);
					}
	                var rows = record.getElements();
	                rows.forEach((row) => {
						frag.appendChild(row);
					});
				});
			});
		}

		// Remember that we last sorted by this column
		this._sortHeaderPrevious = currentSortHeader;
		this._tableBody.appendChild(frag);
	}


	// Given an array of record IDs, send the array through the filtering function for each of
	// the header widgets, and each of the options menu widgets, then return the filtered array.
	applyAllWidgetFiltering(filteredSequence:number[]):number[] {
		// Give each header widget a chance to apply filtering
        this._headerWidgets.forEach((widget) => {
            filteredSequence = widget.applyFilterToIDs(filteredSequence);
        });

		// Give each widget in the options menu a chance to apply filtering
        this._optionsMenuWidgets.forEach((widget) => {
			filteredSequence = widget.applyFilterToIDs(filteredSequence);
		});
		return filteredSequence;
	}


	// Add up all the column counts in the headerspec, to arrive at a grand total for the table.
	getSpec():any {
        return this._spec;	// F*** type conversion F*** things up when subclassing
    }


	// Add up all the column counts in the headerspec, to arrive at a grand total for the table.
	countTotalColumns():number {
        return this._spec.tableHeaderSpec.reduce((prev, v):number => {
        	if (v.headerRow) {
        		if (v.headerRow > 1) {
        			return prev;
        		}
        	}
        	return prev + (v.colspan ? v.colspan : 1);
        }, 0);
	}


	// Walk through each header in the spec, and look for a "sortBy" function.
	// If one is found, use it to construct a sorting function
	private _buildAllTableSorters():DataGrid {
        this._spec.tableHeaderSpec.forEach((header) => {
			if (header.sortBy) {
				header.sortFunc = this.buildTableSorter(header.sortBy);
			}
		});
        return this;
	}


	// Given a comparison function,
	// construct a function suitable for passing to Javascript's "sort".
	buildTableSorter(lookupFunc: (rowIndex:number) => any): (x:number, y:number) => number {
		return (rowIndexA:number, rowIndexB:number) => {
            var a = lookupFunc.call(this._spec, rowIndexA);
            var b = lookupFunc.call(this._spec, rowIndexB);
            return (<any>(a > b) - <any>(b > a)); // true becomes 1, false becomes 0
		};
	}


	// Start with the array of IDs given in the spec.  Then, for each header, build a sorted copy of the array,
	// and save the sorted copy into the header information.
	//
	// Some sort sequences may rely on the sort sequences of other headers.
	// In the code below, these are followed like a dependency tree.
	// We do this by tracking the unsorted headers in a set, and looping through the set.
	// Every time we find a header that we can successfully sort - whether because the prerequisite header is already
	// sorted, or because it has no prerequisite - we sort it and remove it from the set.
	// If we ever loop through the set and fail to remove even one item from it, we give up,
	// since there must be a dependency loop.
	// It's not the fastest method on the planet, but it's good enough, since we'll probably never have any more than 10 or so headers.
	private _buildTableSortSequences():DataGrid {
		var unsortedHeaders:DataGridHeaderSpec[] = [];
		var sortedAtLeastOneNewHeader:boolean = false;
        // Declare all the headers unsorted, and add them to the unsorted set.
        this._spec.tableHeaderSpec.forEach((header) => {
            if (header.sortFunc) {               // only add headers with sort functions
    			unsortedHeaders.unshift(header); // add in front, so set is reversed
    			header.sorted = false;
    			header.sortSequence = [];
    			header.sortSequenceReversed = [];
            }
		});
        do {
            sortedAtLeastOneNewHeader = false;
            // use slice so that splice inside the callback does not interfere with loop
            unsortedHeaders.slice(0).forEach((header, index) => {
                if (header.prerequisitesSorted(this._spec)) {
                    header.initSortSequence(this._spec);
                    header.sortSequence.sort(header.sortFunc);
                    // copy to new array via slice, then reverse sort
                    header.sortSequenceReversed = header.sortSequence.slice(0).reverse();
                    header.sorted = true;
                    unsortedHeaders.splice(index, 1);
                    sortedAtLeastOneNewHeader = true;
                }
            });
        } while (sortedAtLeastOneNewHeader);
        return this;
	}


	private _buildTableHeaders():HTMLElement[] {
		// Find the minimum number of rows we need to create to contain all the headers
		var maxheaderRow:number = this._spec.tableHeaderSpec.reduce(
                (prev:number, v) => { return Math.max(prev, v.headerRow || 0); }, 1);

		// Create enough rows to contain the headers (usually just 1)
		var rowElements:HTMLElement[] = [];
	 	for (var i=0; i < maxheaderRow; i++) {
            var row = $(document.createElement("tr")).addClass('columnLabels');
			rowElements.push(row[0]);
		}

		// Run through each individual header, create it according to the specs, and add it to the appropriate row.
        this._spec.tableHeaderSpec.forEach((header, i, src) => {
            var commonCss:{} = {
                'width': header.width ?
                    (header.width.substr(-1) !== '%' ? header.width + 'px' : header.width) :
                    undefined,
            };
            var css:{} = $.extend({
                'text-align': header.align,
                'vertical-align': header.valign,
                'display': header.display
            }, commonCss);
            header.element = document.createElement("th");
            var cell:JQuery = $(header.element).css(css).attr({
                    'id': header.id,
                    'colspan': header.colspan > 1 ? header.colspan : undefined,
                    'rowspan': header.rowspan > 1 ? header.rowspan : undefined,
                    'class': header.size === 's' ? 'smaller' : undefined
                }).appendTo(rowElements[Math.max(header.headerRow || 1, 1) - 1]);
            if (header.sortBy) {
            	cell.addClass('sortheader');
            }
            if (header.name) {
	            $(document.createElement("div")).appendTo(cell).text(header.name)
    	            .attr({ 'class': header.nowrap ? 'nowrap' : undefined }).css(commonCss);
    	    }
		});
		// Remove the right-side border line from the last element of each row
        rowElements.forEach((row) => {
        	var l:any = row.lastChild;
        	if (l) { l.style.borderRight = '0' }
        });

		return rowElements;
	}


	// Build the rows (and the contents of the rows) for each record in the data.
	// (See the DataGridDataCell class.)
	private _allocateTableRowRecords():DataGrid {
		this._recordElements = new DataGridRecordSet();
        this._spec.getRecordIDs().forEach((id) => {
            this._recordElements[id] = new DataGridRecord(this._spec, id);
		});
		return this;
	}


	// Assemble table rows - disclosed and undisclosed versions (with callbacks) -
	// that act as titles for the different groups when the table is in grouping mode.
	private _buildRowGroupTitleRows():DataGrid {
		this._spec.tableRowGroupSpec.forEach((oneGroup, index) => {
			oneGroup.disclosed = true;
			oneGroup.memberRecords = [];

            var row = oneGroup.disclosedTitleRowJQ = $(oneGroup.disclosedTitleRow = document.createElement("tr"))
                .addClass('groupHeader').click(() => this._collapseRowGroup(index));
            var cell = $(document.createElement("td")).appendTo(row);
            $(document.createElement("div")).appendTo(cell).text("\u25BA " + oneGroup.name);
            if (this._totalColumnCount > 1) {
                cell.attr('colspan', this._totalColumnCount);
            }

            row = oneGroup.undisclosedTitleRowJQ = $(oneGroup.undisclosedTitleRow = document.createElement("tr"))
                .addClass('groupHeader').click(() => this._expandRowGroup(index));
            cell = $(document.createElement("td")).appendTo(row);
            $(document.createElement("div")).appendTo(cell).text("\u25BC " + oneGroup.name);
            if (this._totalColumnCount > 1) {
                cell.attr('colspan', this._totalColumnCount);
            }
		});
        return this;
	}


	// The server code hooks table headers with this function.
	clickedSort(header:DataGridHeaderSpec) {

		$(header.element).addClass('sortwait');
		// We turn the rest of the operation into an event so the browser
		// will (probably) refresh, showing our 'please wait' style
		this.scheduleTimer('_sortIt', () => this._sortIt(header));
	}


	// Handle the "sortable" CSS class in a table.
	private _prepareSortable():void {
		// Add a click event for every header cell that identifies as sortable
        this._spec.tableHeaderSpec.forEach((header) => {
            if (!header.sortBy) {
                return;
            }
            $(header.element).click(() => this.clickedSort(header));
		});
	}


	// Sort by a particular column.
	// thisth is the <th> element for the table header.
	// sameSortOrder is optional. If it's true, then we'll use the same sort order as thisth previously used.
	private _sortIt(header:DataGridHeaderSpec, sameSortOrder:boolean = false):void {
		this._sortHeaderCurrent = header;

		// If we just sorted on this column, and reversesort has been defined but is zero,
		// do a reverse sort.
		if (sameSortOrder == false) {
            // if previous header and new header are same, flip the reversed flag
			if (this._sortHeaderPrevious == header) {
                header.sortCurrentlyReversed = !header.sortCurrentlyReversed;
			}
		}
		this.arrangeTableDataRows();
	}


	private _clickedOptMenuWhileOff():void {
        $(this._optionsMenuBlockElement).add(this._optionsLabelOnElement).removeClass('off');
	}


	private _clickedOptMenuWhileOn():void {
        $(this._optionsMenuBlockElement).add(this._optionsLabelOnElement).addClass('off');
	}


	private _collapseRowGroup(groupIndex):void {
		var rowGroup = this._spec.tableRowGroupSpec[groupIndex];
		rowGroup.disclosed = false;
		this.scheduleTimer('arrangeTableDataRows', () => this.arrangeTableDataRows());
	}


	private _expandRowGroup(groupIndex):void {
		var rowGroup = this._spec.tableRowGroupSpec[groupIndex];
		rowGroup.disclosed = true;
		this.scheduleTimer('arrangeTableDataRows', () => this.arrangeTableDataRows());
	}


	turnOnRowGrouping():void {
		this._groupingEnabled = true;
		this.scheduleTimer('arrangeTableDataRows', () => this.arrangeTableDataRows());
	}


	turnOffRowGrouping():void {
		this._groupingEnabled = false;
		this.scheduleTimer('arrangeTableDataRows', () => this.arrangeTableDataRows());
	}


	clickedOptionWidget(event:Event):void {
		var control = event.target;	// Grab the checkbox that sent the event
		this.scheduleTimer('arrangeTableDataRows', () => this.arrangeTableDataRows());
	}


	clickedHeaderWidget(headerWidget:DataGridWidget):void {
		this.scheduleTimer('arrangeTableDataRows', () => this.arrangeTableDataRows());
	}


	// 'control' is a column visibility checkbox
	private _clickedColVisibilityControl(event:Event):DataGrid {
		var control:any = event.target;	// Grab the checkbox that sent the event
		// Acquire the value in a way that doesn't make Typescript throw a hissy-fit
		var val = parseInt(control.getAttribute('value'), 10) - 1;
		if (control.checked) {
			this.showColumn(val);
		} else {
			this.hideColumn(val);
		}
        return this;
	}


	// 'control' is a column visibility checkbox
	showColumn(columnIndex:number):void {
		// The value points to an entry in the column groups specification
		if (!this._spec.tableColumnGroupSpec[columnIndex]) {
			return;
		}
		var group = this._spec.tableColumnGroupSpec[columnIndex];
		if (group.currentlyHidden) {
			group.currentlyHidden = false;
			if (group.revealedCallback) {
				group.revealedCallback(columnIndex, this._spec, this);
			}
			this.scheduleTimer('_updateColumnSettings', () => this._updateColumnSettings());
			this.scheduleTimer('_applyColumnVisibility', () => this._applyColumnVisibility());
		}
	}


	// 'control' is a column visibility checkbox
	hideColumn(columnIndex:number):void {
		// The value points to an entry in the column groups specification
		if (!this._spec.tableColumnGroupSpec[columnIndex]) {
			return;
		}
		var group = this._spec.tableColumnGroupSpec[columnIndex];
		if (!group.currentlyHidden) {
			group.currentlyHidden = true;
			this.scheduleTimer('_updateColumnSettings', () => this._updateColumnSettings());
			this.scheduleTimer('_applyColumnVisibility', () => this._applyColumnVisibility());
		}
	}


	// The server binds this. 'this' is a checkbox.
	private _updateColumnSettings():DataGrid {

		// Fetch the all-important pagename attribute
		var id = this._spec.tableSpec.id;
		// Build an AJAX URL containing the required action and the pagename
		var url = "PreferencesAjaxResp.cgi?action=_updateColumnSettings&pagename=" + encodeURIComponent(id);

		// Query every checkbox in the column visibility pulldown
		// and send its name and checked status back as part of the query.
        this._spec.tableColumnGroupSpec.forEach((group, index) => {
            if (!group.showInVisibilityList || !group.checkboxElement) {
                return;
            }
			var j = group.checkboxElement;
			url += "&" + (index + 1) + "=" + encodeURIComponent(j.checked.toString());
		});
		$.ajax({
			url: url,
			dataTypeString: "json",
			success: function(data, textStatus, jqXHR) {}
		});
        return this;
	}


	// Schedule a call to the given function in the near future, and save the timer under the given identifier.
	// Multiple calls to this using the same identifier will reschedule the event, removing the old timer.
	scheduleTimer(uid:string, func:() => any):DataGrid {
		if (this._timers[uid]) { clearTimeout ( this._timers[uid] ); }
		this._timers[uid] = setTimeout( func, 10 );
        return this;
	}


    // apply a function to every record ID specified
    applyToRecordSet(func:(rows:DataGridDataRow[], id:number, spec:DataGridSpecBase, grid:DataGrid)=>void, ids:number[]):DataGrid {
        ids.forEach((id) => {
            func.call({}, this._recordElements[id].getDataGridDataRows(), id, this._spec, this);
        });
        return this;
    }


    // retreive the current sequence of records in the DataGrid
    currentSequence():number[] {
        var header:DataGridHeaderSpec = this._sortHeaderCurrent;
        return header.sortCurrentlyReversed ? header.sortSequenceReversed : header.sortSequence;
    }


	// Member variables.
	private _spec:DataGridSpecBase;

	private _table:HTMLElement;
	private _tableBody:HTMLElement;
	private _tableHeaderCell:HTMLElement;
	private _waitBadge:HTMLElement;
	tableTitleSpan:HTMLElement;

	private _headerRows:HTMLElement[];
	private _totalColumnCount:number;
	private _recordElements:DataGridRecordSet;

	private _headerWidgets:DataGridHeaderWidget[];
	private _optionsMenuWidgets:DataGridOptionWidget[];
	private _optionsMenuElement:HTMLElement;

	private _optionsMenuBlockElement:HTMLElement;
	private _optionsLabelOnElement:HTMLElement;
	private _optionsLabelOffElement:HTMLElement;

	private _groupingEnabled:boolean = false;	// grouping mode off by default
	private _sortHeaderPrevious:DataGridHeaderSpec = null;
	private _sortHeaderCurrent:DataGridHeaderSpec;

	private _timers:{[index:string]:number};
}



// Type definition for the records contained in a DataGrid
class DataGridRecordSet {
    [index:number]:DataGridRecord;
}


// Type definition for the records contained in a DataGrid
class DataGridRecord {
	gridSpec:DataGridSpecBase;
	recordID:number;
    dataGridDataRows:DataGridDataRow[];
	rowElements:HTMLElement[];
	createdElements:boolean;
	stripeStyles:string[];
	stripeStylesJoin:string;
	recentStripeIndex:any;

	constructor(gridSpec:DataGridSpecBase, id:number) {
		this.gridSpec = gridSpec;
		this.recordID = id;
		this.rowElements = [];
		this.dataGridDataRows = [];
		this.stripeStyles = ['stripeRowA','stripeRowB'];
        this.stripeStylesJoin = this.stripeStyles.join(' ');
		this.createdElements = false;
		this.recentStripeIndex = null;
	}


	reCreateElementsInPlace():void {
		// If the elements haven't been created even once, then divert to standard creation and finish.
		if (!this.createdElements) {
			this.createElements();
			return;
		}
		// If we're going to maintain the position of the new rows,
		// we need to find their earlier adjacent sibling, if one exists.
		var previousParent = null;
		var nextSibling = null;
		if (this.dataGridDataRows.length) {
			var lastEl = this.rowElements[this.dataGridDataRows.length-1];
			// Sanity check:  Does it have a parent?  Can't have a valid sibling without a parent.
			if (lastEl.parentNode) {
				previousParent = lastEl.parentNode;
				nextSibling = lastEl.nextSibling;
			}
		}
		// Now that we know these things, we can ditch the rows out of the table.
		this.removeElements();
		// Force recreation.
		this.createdElements = false;
		// The old cells are still referenced in their colSpec objects before this,
		// but calling generateCells again automatically replaces them.
		this.createElements();
		// If recentStripeIndex is null, we haven't applied any striping to the previous row, so we skip it here.
		if (!(this.recentStripeIndex === null)) {
			this.applyStriping(this.recentStripeIndex);
		}
		// Drop the new rows into place where the old rows lived.
		if (previousParent) {
			if (nextSibling) {
	    		this.rowElements.forEach((row) => {
					previousParent.insertBefore(row, nextSibling);
				});
			} else {
	    		this.rowElements.forEach((row) => {
					previousParent.appendChild(row);
				});
			}
		}
	}


	createElements():void {
		if (this.createdElements) {
			return;
		}
		this.rowElements = [];
		this.dataGridDataRows = [];

		var cellsForColumns = {};
        this.gridSpec.tableColumnSpec.forEach((colSpec, index) => {
			cellsForColumns[index] = colSpec.generateCells(this.gridSpec, this.recordID);
        });

        // We will use these indexes to determine when we need to add the next cell, in the sequence of rows.
		var currentRowHeightsForColumns = {};
        this.gridSpec.tableColumnSpec.forEach((colSpec, index) => {
			currentRowHeightsForColumns[index] = 0;
        });

        var addingForRow = 0;
        var moreToAdd:boolean = true;

        // Pull cells off the bottom of the arrays, left to right, assembling the rows one at a time,
        // skipping columns based on the rowspan or colspan of previous cells.  We expect the client of
        // this class to ensure they are declaring a nicely fitted rectangular structure - we don't validate it.
        while (moreToAdd) {
			moreToAdd = false;

	        var addingForColumn = 0;
			var cells:DataGridDataCell[] = [];
			while (addingForColumn < this.gridSpec.tableColumnSpec.length) {
				if (currentRowHeightsForColumns[addingForColumn] > addingForRow) {
					addingForColumn++;
					continue;
				}

				var colCells = cellsForColumns[addingForColumn];
                if (colCells.length) {
                    var c = colCells.shift();
                    // If there are still cells left to use, in any column, after drawing off the one
                    // we're dealing with, then we should run through this loop again.
                    if (colCells.length) {
                        moreToAdd = true;
                    }
                    var nextOpenColumn = addingForColumn + c.colspan;
                    while (addingForColumn < nextOpenColumn) {
                        currentRowHeightsForColumns[addingForColumn] = addingForRow + c.rowspan;
                        addingForColumn++;
                    }
                    cells.push(c);
                } else {
                    // nothing in the current column, skip ahead to next one
                    ++addingForColumn;
                }
			}


	        var r = new DataGridDataRow(this.recordID, cells);
			this.dataGridDataRows.push(r);
			this.rowElements.push(r.getElement());

			addingForRow++;
		}

		this.createdElements = true;
	}


	removeElements() {
    	this.dataGridDataRows.forEach((row) => {
       		row.removeElement();
    	});
    }


	// Like remove, except it doesn't remove JQuery events or data.
	// Used to take the table rows temporarily out of the DOM, like when re-ordering.
	detachElements() {
    	this.dataGridDataRows.forEach((row) => {
       		row.detachElement();
    	});
	}


	getDataGridDataRows():DataGridDataRow[] {
		if (!this.createdElements) {
			this.createElements();
		}
		return this.dataGridDataRows;
	}


	getElements():HTMLElement[] {
		if (!this.createdElements) {
			this.createElements();
		}
		return this.rowElements;
	}


	applyStriping(stripeIndex:number) {
    	var rows = this.getDataGridDataRows();
    	this.recentStripeIndex = stripeIndex;
    	rows.forEach((row) => {
			var rJQ = row.getElementJQ();
        	rJQ.removeClass(this.stripeStylesJoin).addClass(this.stripeStyles[stripeIndex]);
		});
    }
}



// Container class for data rows in the body of the DataGrid table.
// DataGrid instantiates these by passing in an array of the DataGridDataCell objects that will form the content of the row.
class DataGridDataRow {

	rowElement:HTMLElement;
	rowElementJQ:JQuery;
	// Defined or set by the constructor
	recordID:number;
	dataGridDataCells:DataGridDataCell[];
	createdElement:boolean;

	constructor(id:number, cells:DataGridDataCell[]) {
		this.recordID = id;
		this.dataGridDataCells = cells;
		this.createdElement = false;
	}


	createElement() {
		var rowEl:HTMLElement = document.createElement("tr");
		for (var i=0; i < this.dataGridDataCells.length; i++) {
			var c = this.dataGridDataCells[i];
			rowEl.appendChild(c.getElement());
		}

		this.rowElement = rowEl;
		this.createdElement = true;
	}


	removeElement() {
		if (this.createdElement) {
			this.getElementJQ().remove();
		}
	}


	// Like remove, except it doesn't remove JQuery events or data.
	// Used to take the table rows temporarily out of the DOM, like when re-ordering.
	detachElement() {
		if (this.createdElement) {
			this.getElementJQ().detach();
		}
	}


	getElement():HTMLElement {
		if (!this.createdElement) {
			this.createElement();
		}
		return this.rowElement;
	}


	getElementJQ():JQuery {
		if (!this.createdElement) {
			this.createElement();
		}
		if (!this.rowElementJQ) {
			this.rowElementJQ = $(this.rowElement);
		}
		return this.rowElementJQ;
	}
}



// Container class for cells in the body of the DataGrid table.
// DataGrid calls a function defined in DataGridColumnSpec objects to instantiate these,
// passing in a reference to the DataGridSpecBase and a unique identifier for a data record.
class DataGridDataCell {

	// Defined or set by the constructor
    gridSpec:DataGridSpecBase;
	recordID:number;

	// Options potentially set by the constructor
    rowspan:number;
    colspan:number;
    align:string;           // TODO: should be an enum type of: 'left', 'right', 'center'
    valign:string;          // TODO: should be an enum type of: 'top', 'middle', 'bottom', 'baseline'
    maxWidth:string;
    minWidth:string;
    nowrap:boolean;
    hoverEffect:boolean;
    contentFunction:(e:HTMLElement, index:number)=>void;
    contentString:string;
    checkboxWithID:(index:number)=>string;
    customID:(index:number)=>string;
    sideMenuItems:string;

    // Local data
	cellElement:HTMLElement;
	cellElementJQ:JQuery;
	contentContainerElement:HTMLElement;
	checkboxElement:HTMLInputElement;
	hidden:boolean;
	createdElement:boolean;

	constructor(gridSpec:DataGridSpecBase, id:number, opt?:{[index:string]:any}) {
        this.gridSpec = gridSpec;
		this.recordID = id;
		this.hidden = false;
		this.createdElement = false;
        opt = opt || {};
        this.contentFunction = opt['contentFunction'] || function(e, index) {};
        this.contentString = opt['contentString'] || '';
        opt = $.extend({ 'align': 'left' }, opt);
        this.rowspan = opt['rowspan'] || 1;
        this.colspan = opt['colspan'] || 1;
        this.align = opt['align'];
        this.valign = opt['valign'];
        this.maxWidth = opt['maxWidth'];
        this.minWidth = opt['minWidth'];
        this.nowrap = opt['nowrap'];
        this.hoverEffect = opt['hoverEffect'];
        this.checkboxWithID = opt['checkboxWithID'];
        this.customID = opt['customID'];
        this.sideMenuItems = opt['sideMenuItems'];
	}


	createElement() {
		var id = this.recordID;

		var c:HTMLElement = document.createElement("td");
		// If we're adding a checkbox on the left, or a popup side-menu on the right,
		// we need to create a sequence of divs as a scaffolding.
		if (this.checkboxWithID || this.sideMenuItems) {
			// td > div.p
			var dp = document.createElement("div");
			dp.className = 'p';
			c.appendChild(dp);
			// td > div.p > div.q
			var dq = document.createElement("div");
			dq.className = 'q';
			dp.appendChild(dq);
			if (this.checkboxWithID) {
				// td > div.p > div.q > div.r.checkbox
				var dr = document.createElement("div");
				dr.className = 'r checkbox';
				dq.appendChild(dr);
				// td > div.p > div.q > div.r.checkbox > input[checkbox]
				var cbID = this.checkboxWithID.call(this.gridSpec, id);
				var cb = document.createElement("input");
				cb.setAttribute('type', 'checkbox');
				cb.setAttribute('name', cbID);
				cb.setAttribute('id', cbID);
				cb.setAttribute('value', id.toString());
				this.checkboxElement = cb;
				dr.appendChild(cb);
			}
			// td > div.p > div.q > div.r
			var dr = document.createElement("div");
			dr.className = 'r';
			dq.appendChild(dr);
			if (this.sideMenuItems) {
                var mItems = this.sideMenuItems;
                if (mItems.length) {
    				// td > div.p > div.q > div.s
    				var ds = document.createElement("div");
    				ds.className = 's';
    				dq.appendChild(ds);
    				// td > div.p > div.q > div.s > div.t
    				var dt = document.createElement("div");
    				dt.className = 't';
    				ds.appendChild(dt);
    				// td > div.p > div.q > div.s > div.t > ul
    				var ul = document.createElement("ul");
    				dt.appendChild(ul);
    				for (var i=0; i < mItems.length; i++) {
    					// td > div.p > div.q > div.s > div.t > ul > li
    					var li = document.createElement("li");
    					li.innerHTML = mItems[i];
    					ul.appendChild(li);
    				}
                }
			}
			this.contentContainerElement = dr;
		} else {
			// If we're not adding a checkbox or a side menu, construction is a lot easier...
			this.contentContainerElement = c;
		}
		this.contentContainerElement.innerHTML = this.contentString;
		this.contentFunction.call(this.gridSpec, this.contentContainerElement, id);

		var cellClasses = [];

		if (this.colspan > 1) {
			c.setAttribute('colspan', this.colspan.toString(10));
		}
		if (this.rowspan > 1) {
			c.setAttribute('rowspan', this.rowspan.toString(10));
		}
		if (this.customID) {
			c.setAttribute('id', this.customID.call(this.gridSpec, id));
		}

		if (this.hoverEffect) {
			cellClasses.push('popupcell');
		}
		if (this.nowrap) {
			cellClasses.push('nowrap');
		}
		if (this.minWidth) {
			c.style.minWidth = this.minWidth + 'px';
		}
		if (this.maxWidth) {
			c.style.maxWidth = this.maxWidth + 'px';
		}
		if (this.align) {
			c.style.textAlign = this.align;
		}
		if (this.valign) {
			c.style.verticalAlign = this.valign;
		}
		if (this.hidden) {
			cellClasses.push('off');
		}

		if (cellClasses.length > 0) {
			c.className = cellClasses.join(' ');
		}
		this.cellElement = c;
		this.cellElementJQ = $(c);
		if (this.hidden) {
			this.cellElementJQ.addClass('off');
		}

		this.createdElement = true;
	}


	getElement():HTMLElement {
		if (!this.createdElement) {
			this.createElement();
		}
		return this.cellElement;
	}


	getCheckboxElement():HTMLInputElement {
		if (!this.createdElement) {
			this.createElement();
		}
		return this.checkboxElement || null;
	}


	hide():void {
		if (!this.hidden) {
			if (this.createdElement) {
				this.cellElementJQ.addClass('off');
			}
			this.hidden = true;
		}
	}


	unhide():void {
		if (this.hidden) {
			if (this.createdElement) {
				this.cellElementJQ.removeClass('off');
			}
			this.hidden = false;
		}
	}
}



// A placeholder cell when data is still loading
class DataGridLoadingCell extends DataGridDataCell {

    constructor(gridSpec:DataGridSpecBase, id:number, opt?:{[index:string]:any}) {
        super(gridSpec, id, opt);
        this.contentString = '<span class="loading">Loading...</span>';
    }

}



// A general class that acts as a common repository for utility functions for DataGrid widgets.
// It is immediately subclassed into DataGridOptionWidget and DataGridHeaderWidget.
class DataGridWidget {

	dataGridSpec:DataGridSpecBase;
	dataGridOwnerObject:DataGrid;

	constructor(dataGridOwnerObject:DataGrid, dataGridSpec:DataGridSpecBase) {
		this.dataGridOwnerObject = dataGridOwnerObject;
		this.dataGridSpec = dataGridSpec;
	}


	// Utility function to create a label element
	_createLabel(text:string, id:string):HTMLElement {
		var label:HTMLElement = document.createElement("label");
		label.setAttribute('for', id);
		label.appendChild(document.createTextNode(text));
		return label;
	}


	// Utility function to create a checkbox element
	_createCheckbox(id:string, name:string, value:string):HTMLInputElement {
		var cb:HTMLInputElement = document.createElement("input");
		cb.setAttribute('id', id);
		cb.setAttribute('name', name);
		cb.setAttribute('type', 'checkbox');
		cb.setAttribute('value', value);
		return cb;
	}


    // This is called with an array of row elements, and the ID they represent, so the widget can
    //  apply any custom styling it needs. It is called one time for each ID and respective row
    //  array, during the construction of the table rows.
    initialFormatRowElementsForID(dataRowObjects:DataGridDataRow[], rowID:number):void {
        // no special formatting by default
    }


    // Notify the widget that the DataGrid has been updated
    refreshWidget():void {
        // nothing by default
    }
}



// This is the base class for additional widgets that appear in the options menu of a DataGrid table.
// The default behavior is to create a checkbox element with a callback, and pair it with a label element.
//
// Each DataGridOptionWidget needs to implement an applyFilterToIDs function to provide some method for filtering
// a given list of IDs.  This is how the widget affects which rows are displayed in the table.
//
// The DataGridSpec is responsible for instantiating these DataGridOptionWidget-derived objects for a particular table,
// and the DataGrid object is responsible for building the options menu that will store the checkbox and label elements.
class DataGridOptionWidget extends DataGridWidget {

	_createdElements:boolean;
	// The base DataGridOptionWidget provides template code and structure for creating a checkbox with a label,
	// but other UI can be created and used instead.
	checkBoxElement:HTMLInputElement;
	labelElement:HTMLElement;

	constructor(dataGridOwnerObject:DataGrid, dataGridSpec:DataGridSpecBase) {
		super(dataGridOwnerObject, dataGridSpec);
		this._createdElements = false;
	}


	// The uniqueID is provided to assist the widget in avoiding collisions
	// when creating input element labels or other things requiring an ID.
	createElements(uniqueID:string):void {
		var cbID:string = this.dataGridSpec.tableSpec.id+'GenericOptionCB'+uniqueID;
		var cb:HTMLInputElement = this._createCheckbox(cbID, cbID, '1');
		// We need to make sure the checkbox has a callback to the DataGrid's handler function.
		// Among other things, the handler function will call the appropriate filtering functions for all the widgets in turn.
		$(cb).click( (e) => this.dataGridOwnerObject.clickedOptionWidget(e) );
		if (this.isEnabledByDefault()) {
			cb.setAttribute('checked', 'checked');
		}
		this.checkBoxElement = cb;
		this.labelElement = this._createLabel("Name Of Option", cbID);
		this._createdElements = true;
	}


	// This is called to append the widget elements beneath the given element.
	// If the elements have not been created yet, they are created, and the uniqueID is passed along.
	appendElements(container:HTMLElement, uniqueID:string):void {
		if (!this._createdElements) {
			this.createElements(uniqueID);
		}
		container.appendChild(this.checkBoxElement);
		container.appendChild(this.labelElement);
	}


	// This is called with an array of IDs for filtering, and a filtered array is returned.
	// It is acceptable to just return the original array if no filtering needs to be done.
	//
	// It's up to the designer to decide how the state of the widget affects filtering.
	// For example, if the widget is "additive", you would apply filtering if the widget's checkbox
	// is clear, and skip filtering if the checkbox is set, creating the appearance of a checkbox
	// that "adds" rows when checked.
	applyFilterToIDs(rowIDs:number[]):number[] {
        return rowIDs;
	}


	// Returns true if the control is enabled
	getState():boolean {
        return this.checkBoxElement.hasAttribute('checked');
	}


	// Returns true if the control should be enabled by default
	isEnabledByDefault():boolean {
		return false;
	}


	// Sets the enabled state to true or false, based on the given value
	setState(enabled:boolean):void {
		if (enabled) {
			this.checkBoxElement.setAttribute('checked', 'checked');
		} else {
			this.checkBoxElement.removeAttribute('checked');
		}
	}
}



// This is the base class for additional widgets that appear in the header area of a DataGrid table.
//
// The DataGridSpec is responsible for instantiating these DataGridOptionWidget-derived objects for a particular table,
// and the DataGrid object is responsible for building the header area that will contain the widgets.
class DataGridHeaderWidget extends DataGridWidget {

    private _createdElements:boolean;
	// Whether to add this widget to the header of the table before the view menu, instead of the default of after.
	// This option is set by an accessor function meant to be called shortly after instantiation.
	private _displayBeforeViewMenuFlag:boolean;
	// The base DataGridHeaderWidget provides template code that just creates a text field,
	// but other UI can be created and used instead.
	element:HTMLElement;


	constructor(dataGridOwnerObject:DataGrid, dataGridSpec:DataGridSpecBase) {
		super(dataGridOwnerObject, dataGridSpec);
		this._displayBeforeViewMenuFlag = false;
		this._createdElements = false;
	}


	// The uniqueID is provided to assist the widget in avoiding collisions
	// when creating input element labels or other things requiring an ID.
	createElements(uniqueID:string):void {
        var tBoxID:string = this.dataGridSpec.tableSpec.id + 'text' + uniqueID;
        var tBox = $(this.element = document.createElement("input"))
            .attr({ 'id': tBoxID, 'name': tBoxID, 'size': '20' })
            .addClass('tableControl');
	}


	// This is called to append the widget elements beneath the given element.
	// If the elements have not been created yet, they are created, and the uniqueID is passed along.
	appendElements(container:HTMLElement, uniqueID:string):void {
		if (!this._createdElements) {
			this.createElements(uniqueID);
            this.createdElements(true);
		}
        container.appendChild(this.element);
	}


    createdElements():boolean;
    createdElements(flag:boolean):DataGridHeaderWidget;
    createdElements(flag?:boolean):any {
        if (flag === undefined) {
            return this._createdElements;
        } else {
            this._createdElements = flag;
            return this;
        }
    }

	// Whether to add this widget to the header of the table before the view menu, instead of the default of after.
	// Pass in "false" to reverse the setting.
    displayBeforeViewMenu():boolean;
    displayBeforeViewMenu(flag:boolean):DataGridHeaderWidget;
	displayBeforeViewMenu(flag?:boolean):any {
        if (flag === undefined) {
            return this._displayBeforeViewMenuFlag;
        } else {
    		this._displayBeforeViewMenuFlag = flag;
            return this;
        }
	}


	// This is called with an array of record IDs for filtering, and a filtered array is returned.
	// It is acceptable to just return the original array if no record filtering needs to be done.
	applyFilterToIDs(rowIDs:number[]):number[] {
		return rowIDs;
	}
}



// A generic "Select All" header widget, appearing as a button.
// When clicked, it walks through every row and cell looking for DataGrid-created checkboxes,
// and checks every one it finds.
class DGSelectAllWidget extends DataGridHeaderWidget {

	constructor(dataGridOwnerObject:DataGrid, dataGridSpec:DataGridSpecBase) {
		super(dataGridOwnerObject, dataGridSpec);
	}


	// The uniqueID is provided to assist the widget in avoiding collisions
	// when creating input element labels or other things requiring an ID.
	createElements(uniqueID:string):void {
        var buttonID:string = this.dataGridSpec.tableSpec.id + 'SelAll' + uniqueID;
		var button = $(this.element = document.createElement("input"));
        button.attr({ 'id': buttonID, 'name': buttonID, 'value': 'Select All' })
            .addClass('tableControl')
            .click(() => this.clickHandler());
        this.element.setAttribute('type', 'button'); // JQuery attr cannot do this
	}


	clickHandler():void {
        var sequence = this.dataGridOwnerObject.currentSequence();
        // Have DataGrid apply function to everything in current sequence
        this.dataGridOwnerObject.applyToRecordSet((rows) => {
            // each row in sequence
            rows.forEach((row) => {
                // each cell in row
                row.dataGridDataCells.forEach((cell) => {
                    // if the cell has a checkbox, check it
                    cell.checkboxElement && (cell.checkboxElement.checked = true);
                });
            });
        }, sequence);
	}
}



// Here's an example of a working DataGridHeaderWidget.
// It's a search field that narrows the set of rows to ones that contain the given string.
class DGSearchWidget extends DataGridHeaderWidget {

	searchBoxElement:HTMLInputElement;
	placeHolder:string;
	fieldSize:number;
	typingTimeout:number;
	typingDelay:number;
	lastKeyPressCode:number;
	previousSelection:string;
	minCharsToTriggerSearch:number;
	getsFocus:boolean;	// If true, the search box should be configured to claim focus as soon as the page is loaded


	constructor(dataGridOwnerObject:DataGrid, dataGridSpec:DataGridSpecBase, placeHolder:string, size:number, getsFocus:boolean) {
		super(dataGridOwnerObject, dataGridSpec);
		this.placeHolder = placeHolder;
		this.fieldSize = size;
		this.getsFocus = getsFocus;
		this.typingTimeout = null;
		this.typingDelay = 330;
		this.lastKeyPressCode = null;
		this.previousSelection = null;
		this.minCharsToTriggerSearch = 1;
	}


	// The uniqueID is provided to assist the widget in avoiding collisions
	// when creating input element labels or other things requiring an ID.
	createElements(uniqueID:string):void {
        var sBoxID:string = this.dataGridSpec.tableSpec.id + 'SearchBox' + uniqueID;
        var sBox:JQuery = $(this.element = document.createElement("input"))
            .attr({ 'id': sBoxID, 'name': sBoxID, 'size': this.fieldSize, 'placeholder': this.placeHolder })
            .addClass('tableControl searchBox').keydown((e) => this.inputKeyDownHandler(e));
        this.element.setAttribute('type', 'text'); // JQuery .attr() cannot set this
        if (this.getsFocus) {
            sBox.attr('autofocus', 'autofocus');
        }
	}


	inputKeyDownHandler(e) {
		// track last key pressed
		this.lastKeyPressCode = e.keyCode;
		switch (e.keyCode) {
			case 38: // up
				e.preventDefault();
				break;
			case 40: // down
				e.preventDefault();
				break;
			case 9:  // tab
				break;
			case 13: // return
				e.preventDefault();
				break;
			default:
				if (this.typingTimeout) {
					clearTimeout(this.typingTimeout);
				}
				this.typingTimeout = setTimeout(this.typingDelayExpirationHandler, this.typingDelay);
				break;
		}
	}


	// (Note: This syntax causes "this" to behave in a non-Javascript way
	// see http://stackoverflow.com/questions/16157839/typescript-this-inside-a-class-method )
	typingDelayExpirationHandler = () => {
		// ignore if the following keys are pressed: [del] [shift] [capslock]
		//if (this.lastKeyPressCode == 46) {
		//	return;
		//}
		// ignore if the following keys are pressed: [del] [shift] [capslock]
		if (this.lastKeyPressCode > 8 && this.lastKeyPressCode < 32) {
			return;
		}
		var v = $(this.element).val();
		if (v == this.previousSelection) {
			return;
		}
		this.previousSelection = v;
		this.dataGridOwnerObject.clickedHeaderWidget(this);
	}


	// This is called with an array of record IDs for filtering, and a filtered array is returned.
	// It is acceptable to just return the original array if no record filtering needs to be done.
	applyFilterToIDs(rowIDs:number[]):number[] {

		var v = this.previousSelection;
		if (v == null) {
			return rowIDs;
		}
		if (v.length < this.minCharsToTriggerSearch) {
			return rowIDs;
		}

		v = v.trim();                // Remove leading and trailing whitespace
		v = v.toLowerCase();
		v = v.replace(/\s\s*/, ' '); // Replace internal whitespace with single spaces

		// If there are multiple words, we match each separately.
        // We will not attempt to match against empty strings, so we filter those out if any slipped through
        var queryStrs = v.split(' ').filter((one) => { return one.length > 0; });

		var filteredIDs = [];
        this.dataGridOwnerObject.applyToRecordSet((rows, id) => {
            rows.forEach((row) => {
                row.dataGridDataCells.forEach((cell) => {
                    if (cell.createdElement) {
	                    var text = cell.contentContainerElement.textContent.toLowerCase();
    	                var match = queryStrs.some((v) => {
    	                	// TODO: Sholdn't this be text.length >= v.length ?
        	                return text.length > v.length && text.indexOf(v) >= 0;
            	        });
                	    if (match) {
                    	    filteredIDs.push(id);
                   		}
                   	}
                });
            });
        }, rowIDs);
		return filteredIDs;
	}
}



interface DGPageDataSource {

    pageSize():number;
    pageSize(size:number):DGPageDataSource;
    pageSize(size?:number):any;
    totalOffset():number;
    totalOffset(offset:number):DGPageDataSource;
    totalOffset(offset?:number):any;
    totalSize():number;
    totalSize(size:number):DGPageDataSource;
    totalSize(size?:number):any;
    viewSize():number;
    query():string;
    query(query:string):DGPageDataSource;
    query(query?:string):any;
    pageDelta(delta:number):DGPageDataSource;
    requestPageOfData(callback?:(success:boolean) => void):DGPageDataSource;

}



// This is a widget that will place controls for paging
class DGPagingWidget extends DataGridHeaderWidget {

    private source:DGPageDataSource;
    private widgetElement:HTMLElement;
    private labelElement:HTMLElement;
    private nextElement:HTMLElement;
    private prevElement:HTMLElement;
    private requestDone:(success:boolean) => void = (success:boolean):void => {
        if (success) {
            this.dataGridOwnerObject.triggerDataReset();
        }
    };


    constructor(dataGridOwnerObject:DataGrid, dataGridSpec:DataGridSpecBase, source:DGPageDataSource) {
        super(dataGridOwnerObject, dataGridSpec);
        this.source = source;
        this.displayBeforeViewMenu(true);
    }


    // This is called to append the widget elements beneath the given element.
    // If the elements have not been created yet, they are created, and the uniqueID is passed along.
    appendElements(container:HTMLElement, uniqueID:string):void {
        if (!this.createdElements()) {
            $(this.widgetElement = document.createElement('div'))
                .appendTo(container);
            $(this.labelElement = document.createElement('span'))
                .appendTo(this.widgetElement);
            $(this.prevElement = document.createElement('a'))
                .attr('href', '#').css('margin', '0 5px')
                .text('< Previous').prop('disabled', true)
                .appendTo(this.widgetElement)
                .click(() => {
                    this.source.pageDelta(-1).requestPageOfData(this.requestDone);
                    return false;
                });
            $(this.nextElement = document.createElement('a'))
                .attr('href', '#').css('margin', '0 5px')
                .text('Next >').prop('disabled', true)
                .appendTo(this.widgetElement)
                .click(() => {
                    this.source.pageDelta(1).requestPageOfData(this.requestDone);
                    return false;
                });
            this.createdElements(true);
        }
        this.refreshWidget();
    }

    refreshWidget() {
        var totalSize:number = this.source.totalSize();
        var viewSize:number = this.source.viewSize();
        var start:number = this.source.totalOffset();
        var labelText;
        if (totalSize) {
            labelText = [ 'Displaying ', start + 1, '-', start + viewSize, ' of ', totalSize ].join('');
        } else {
            labelText = 'No results found!';
        }
        $(this.labelElement).text(labelText);
        $(this.prevElement).prop('disabled', !start);
        $(this.nextElement).prop('disabled', start + viewSize >= totalSize);
    }
}



// Define the TableSpec object used by DataGridSpecBase
class DataGridTableSpec {

    name:string;            // Label to put in the title header
    id:string;              // A unique ID string for this table, to cat with other ID strings for generated table elements
    defaultSort:number;     // Index of header to sort by default
    showHeader:boolean;     // Whether to create a header area at the top of the table
    applyStriping:boolean;  // Whether to apply horizontal striping styles to alternate rows

    constructor(id:string, opt?:{[index:string]:any}) {
        this.id = id;       // ID is required, initialize sensible defaults for everything else
        opt = $.extend({ 'name': '', 'defaultSort': 0, 'showHeader': true, 'applyStriping': true }, opt);
        this.name = opt['name'];
        this.defaultSort = opt['defaultSort'];
        this.showHeader = opt['showHeader'];
        this.applyStriping = opt['applyStriping'];
    }
}



// Define the HeaderSpec object used by DataGridSpecBase
class DataGridHeaderSpec {
    name:string;            // The name that appears in the header cell, and in the column show/hide widget
    id:string;              // An ID to assign to the element
    align:string;           // TODO: should be an enum type of: 'left', 'right', 'center'
    valign:string;          // TODO: should be an enum type of: 'top', 'middle', 'bottom', 'baseline'
    nowrap:boolean;         // If set, add a style that prevents long strings from wrapping in the cell
    rowspan:number;         // Number to put in a rowspan for the header.
    colspan:number;         // Number to put in a colspan for the header.
    headerRow:number;       // Which row to place this header in, starting with 1 as the first row.
                            // Used when constructing multi-row header sections that use rowspan and colspan tags to make sub-headers.
                            // Headers are inserted into their indicated rows in the same relative order as they are listed in this spec.
                            // Leaving this out will place the header in the first row.
    columnGroup:number;     // The column group this header belongs to.  Used for hiding and showing columns.
    display:string;         // TODO: should be an enum type of: 'none', 'inline', 'block', 'list-item', 'inline-block', and possibly the 'inline-table' and 'table-*' values
    size:string;            // TODO: should be an enum of accepted values: 'm', 's'
    width:string;           // If present, set the header (and thereby the whole column below it) to a fixed width.
    sortBy:(index:number)=>any;
                            // A function resolving a row ID to a value we can use for sorting by this header
    sortAfter:number;       // The index of another header that we will base these sorting results on (e.g. sort by Description, then by Study Name)
                            // Leave this property empty if there is no sorting prerequisite.
    //
    // These are internal values that should not be defined by spec
    //
    hidden:boolean;
    element:HTMLElement;
    sortFunc:(a:number,b:number)=>number;
    sortSequence:number[];
    sortSequenceReversed:number[];
    sortCurrentlyReversed:boolean;
    sorted:boolean;

    constructor(group:number, id:string, opt?:{[index:string]:any}) {
        this.columnGroup = group;
        this.id = id;       // ID is required, initialize sensible defaults for everything else
        opt = $.extend({ 'name': '', 'align': 'left', 'size': 'm', 'sortAfter': -1 }, opt);   // most things can be null
        this.name = opt['name'];
        this.align = opt['align'];
        this.valign = opt['valign'];
        this.nowrap = opt['nowrap'];
        this.rowspan = opt['rowspan'];
        this.colspan = opt['colspan'];
        this.headerRow = opt['headerRow'];
        this.display = opt['display'];
        this.size = opt['size'];
        this.width = opt['width'];
        this.sortBy = opt['sortBy'];
        this.sortAfter = opt['sortAfter'];
    }


    initSortSequence(spec:DataGridSpecBase):DataGridHeaderSpec {
        if (this.sortAfter >= 0) {
            // if there is a prerequisite, init from its sort sequence
            this.sortSequence = spec.tableHeaderSpec[this.sortAfter].sortSequence.slice(0);
        } else {
            // otherwise go to the original source
            this.sortSequence = spec.getRecordIDs();
        }
        return this;
    }


    prerequisitesSorted(spec:DataGridSpecBase):boolean {
        // make sure all prerequisites are sorted
        if (this.sortAfter >= 0) {
            return spec.tableHeaderSpec[this.sortAfter].sorted;
        }
        return true;
    }
}



// Define the ColumnSpec object used by DataGridSpecBase
class DataGridColumnSpec {
    columnGroup:number;
    generateCellsFunction:(gridSpec:DataGridSpecBase, index:number)=>DataGridDataCell[];

    //
    // These are internal values that should not be defined by spec
    //
    createdDataCellObjects:{[id:number]:DataGridDataCell[]};

    constructor(group:number, generateCells:(gridSpec:DataGridSpecBase, index:number)=>DataGridDataCell[]) {
        this.columnGroup = group;
        this.generateCellsFunction = generateCells;
        this.createdDataCellObjects = {};
    }


    generateCells(gridSpec:DataGridSpecBase, index:number):DataGridDataCell[] {
    	var c = this.generateCellsFunction(gridSpec, index);
    	this.createdDataCellObjects[index] = c.slice(0);
	  	return c;
    }


    clearEntireIndex(index:number):void {
        this.createdDataCellObjects = {};
    }


    clearIndexAtID(index:number):void {
    	delete this.createdDataCellObjects[index];
    }


    cellIndexAtID(index:number):DataGridDataCell[] {
        return this.createdDataCellObjects[index];
    }


    getEntireIndex():DataGridDataCell[] {
    	var cells:DataGridDataCell[] = [];
		for (var key in this.createdDataCellObjects) {
			var a = this.createdDataCellObjects[key];
			if (a) {
				a.forEach((b) => { cells.push(b)});	// Much faster than repeated concats
			}
		}
    	return cells;
    }
}



// Define the ColumnGroupSpec object used by DataGridSpecBase
class DataGridColumnGroupSpec {
    name:string;                    // Readable label string for this column group
    showInVisibilityList:boolean;   // Whether to place this column in the show/hide list
    hiddenByDefault:boolean;        // Flag if group is hidden by default
    // callback for when a column transitions from hidden to visible
    revealedCallback:(index:number, spec:DataGridSpecBase, grid:DataGrid)=>void;

    //
    // These are internal values that should not be defined by spec
    //
    currentlyHidden:boolean;
    memberHeaders:DataGridHeaderSpec[];
    memberColumns:DataGridColumnSpec[];
    checkboxElement:HTMLInputElement;

    constructor(label:string, opt?:{[index:string]:any}) {
        this.name = label;
        opt = $.extend({ 'showInVisibilityList': true }, opt);
        this.showInVisibilityList = opt['showInVisibilityList'];
        this.hiddenByDefault = opt['hiddenByDefault'];
        this.revealedCallback = opt['revealedCallback'];
    }
}



// Define the RowGroupSpec object used by DataGridSpecBase
class DataGridRowGroupSpec {
    name:string;

    //
    // These are internal values that should not be defined by spec
    //
    disclosed:boolean;
    disclosedTitleRow:HTMLElement;
    disclosedTitleRowJQ:JQuery;
    undisclosedTitleRow:HTMLElement;
    undisclosedTitleRowJQ:JQuery;
    memberRecords:DataGridRecord[];

    constructor(label:string) {
        this.name = label;
    }
}



// Users of DataGrid should derive from this class, altering the constructor to
// provide a specification for the layout, interface, and data sources of their DataGrid table,
// and override the callbacks to customize functionality.
// Then, when they instantiate a DataGrid, they should provide an instance of this derived DataGridSpacBase.
// As an example, this base class is set up to render the Studies table on the main page of the EDD.
class DataGridSpecBase {

	// These will all be defined or set by the constructor
	tableSpec:DataGridTableSpec;
	tableHeaderSpec:DataGridHeaderSpec[];
	tableColumnSpec:DataGridColumnSpec[];
	tableColumnGroupSpec:DataGridColumnGroupSpec[];
	tableRowGroupSpec:DataGridRowGroupSpec[];
	tableElement:HTMLElement;


	constructor() {
		this.tableElement = this.getTableElement();
		this.tableSpec = this.defineTableSpec();
		this.tableHeaderSpec = this.defineHeaderSpec();
		this.tableColumnSpec = this.defineColumnSpec();
		this.tableColumnGroupSpec = this.defineColumnGroupSpec();
		this.tableRowGroupSpec = this.defineRowGroupSpec();
	}

	// All of these "define" functions should be overridden


	// Specification for the table as a whole
	defineTableSpec():DataGridTableSpec {
        return new DataGridTableSpec('uniquestring', { 'name': 'Awesome Table' });
	}


	// Specification for the headers along the top of the table
	defineHeaderSpec():DataGridHeaderSpec[] {
		return [
            new DataGridHeaderSpec(1, 'hName', { 'name': 'Name' }),
            new DataGridHeaderSpec(2, 'hDesc', { 'name': 'Description' })
        ];
	}


	// Specification for each of the data columns that will make up the body of the table
	defineColumnSpec():DataGridColumnSpec[] {
		return [
            new DataGridColumnSpec(1, (gridSpec:DataGridSpecBase, index:number):DataGridDataCell[] => {
           		// Create cell(s) for a given record ID, for column 1
            	return [new DataGridDataCell(gridSpec, index)]; 
           	}),
            new DataGridColumnSpec(2, (gridSpec:DataGridSpecBase, index:number):DataGridDataCell[] => {
           		// Create cell(s) for a given record ID, for column 2
            	return [new DataGridDataCell(gridSpec, index)]; 
           	}),
		];
	}


	// Specification for each of the groups that the headers and data columns are organized into
	defineColumnGroupSpec():DataGridColumnGroupSpec[] {
		return [
            new DataGridColumnGroupSpec('Name', { 'showInVisibilityList': false }),
            new DataGridColumnGroupSpec('Description')
		];
	}


	// Specification for the groups that rows can be gathered into
	defineRowGroupSpec():DataGridRowGroupSpec[] {
		return [];
	}


	// When passed a record ID, returns the row group that the record is a member of.
	getRowGroupMembership(recordID:number):number {
		return 0;
	}


	// The table element on the page that will be turned into the DataGrid.  Any preexisting table content will be removed.
	getTableElement():HTMLElement {
		return document.getElementById("studiesTable");
	}


	// An array of unique identifiers, used to identify the records in the data set being displayed
	getRecordIDs():number[] {
		return [];
	}


	// This is called to generate the array of custom header widgets.
	// The order of the array will be the order they are added to the header bar.
	// It's perfectly fine to return an empty array.
	createCustomHeaderWidgets(dataGrid:DataGrid):DataGridHeaderWidget[] {
		// Create a single widget for showing disabled Studies
        var array:DataGridHeaderWidget[] = [];
        array.push(new DGSearchWidget(dataGrid, this, 'Search Studies', 40, true));
        return array;
	}


	// This is called to generate the array of custom options menu widgets.
	// The order of the array will be the order they are displayed in the menu.
	// It's perfectly fine to return an empty array.
	createCustomOptionsWidgets(dataGrid:DataGrid):DataGridOptionWidget[] {
		var widgetSet:DataGridOptionWidget[] = [];

		// Create a single widget for showing only the Studies that belong to the current user
        //		var onlyMyStudiesWidget = new DGOnlyMyStudiesWidget(dataGrid, this);
        //		widgetSet.push(onlyMyStudiesWidget);
		// Create a single widget for showing disabled Studies
        //		var disabledStudiesWidget = new DGDisabledStudiesWidget(dataGrid, this);
        //		widgetSet.push(disabledStudiesWidget);
		return widgetSet;
	}


	// This is called after everything is initialized, including the creation of the table content.
	onInitialized(dataGrid:DataGrid):void {
		// Wire-in our custom edit fields for the Studies page
		IndexPage.initDescriptionEditFields();
	}


	// This is called when a data reset is triggered, but before the table rows are rebuilt.
	onDataReset(dataGrid:DataGrid):void {
		return;	// Do nothing by default.
	}


	// This is called when a partial data reset is triggered, but before the table rows are rebuilt.
	// A partial data reset is one where a collection of records have been specified for re-parsing,
	// and will be mixed-in with the currently rendered collection afterwards.
	onPartialDataReset(dataGrid:DataGrid, records:number[]):void {
		return;	// Do nothing by default.
	}


	// Called when the user hides or shows rows.
	onRowVisibilityChanged():void {

	}

	// This is called to generate a group name. You can process your data however
	// you want in order to come up with a name.
	generateGroupName(dataGrid:DataGrid, groupID:string):string {
		return "Group " + groupID;
	}

	// This is called when the grouping setting is changed, in case
	// you want to persist the setting somewhere.
	onUpdatedGroupingEnabled(dataGrid:DataGrid, enabled:boolean):void {
	}

}


