/// <reference path="typescript-declarations.d.ts" />
// Code for supporting drag-select
var Dragboxes;
(function (Dragboxes) {
    var globalChecked = null;
    function findAndInitAllTables() {
        $('table.dragboxes').each(function (i, table) { return initTable(table); });
    }
    Dragboxes.findAndInitAllTables = findAndInitAllTables;
    function dragEnd(event) {
        globalChecked = null;
        event.data.table.off('mouseover.dragboxes');
    }
    Dragboxes.dragEnd = dragEnd;
    function dragOver(event) {
        if (globalChecked !== null) {
            $(':checkbox', this).prop('checked', globalChecked).trigger('change');
        }
    }
    Dragboxes.dragOver = dragOver;
    function dragStart(event) {
        var $this = $(this), table;
        // mousedown toggles the clicked checkbox value and stores new value in globalChecked
        if (globalChecked === null) {
            // have to check for null to prevent double event from clicking label
            $this.prop('checked', function (i, value) {
                return (globalChecked = !value);
            });
        }
        // also attaches mouseover event to all cells in parent table
        table = $(this).closest('.dragboxes').on('mouseover.dragboxes', 'td', dragOver);
        // wait for mouse to go up anywhere, then end drag events
        $(document).one('mouseup.dragboxes', { 'table': table }, dragEnd);
        return false;
    }
    Dragboxes.dragStart = dragStart;
    function initTable(table) {
        $(table).filter('.dragboxes').on('mousedown.dragboxes', 'td :checkbox', dragStart).on('mousedown.dragboxes', 'td label', dragStart).on('click.dragboxes', 'td :checkbox', function () { return false; });
    }
    Dragboxes.initTable = initTable;
})(Dragboxes || (Dragboxes = {}));
//# sourceMappingURL=Dragboxes.js.map