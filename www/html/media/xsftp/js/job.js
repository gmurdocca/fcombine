
function insertNod(parentElement, where, newElement){
if(typeof parentElement=="string"){parentElement=document.getElementById(parentElement);};
if(!parentElement || parentElement.nodeType!=1){return null;};
where=(where===""/*===, not just == or will think "" is the same as zero*/)?null:where;/*accommodates Opera (7): it apparently translates a parseFloat on an empty string into a zero*/
if(!isNaN(parseFloat(where))){
	where=parseFloat(where);
	if(where<0 || where>=parentElement.childNodes.length){
		where=null;
	}
	else{where=parentElement.childNodes[where];};
};
if(typeof where!="object"){return null;};
return parentElement.insertBefore(newElement, where);
/* keep this comment to reuse freely: http://www.fullposter.com/?1 */
}


function modifyRow(row, id) {
	row.id = "glob_row_" + id;
	td = row.lastChild;
	input = $(td.childNodes[td.childNodes.length - 3]);
	input.setAttribute("id", "id_" + id);
	input.setAttribute("name", id + "-glob");
	// set onclick action to the x button
	del = $(td.childNodes[td.childNodes.length - 2]);
	if (del.attachEvent) {
		// If IE is the browser
		del.onclick = (
			function(i){
				return function(){
					delSourceGlobField(i);
				}
			}
		)(i);
	}
	else {
		// if IE isnt the browser
		del.setAttribute("onclick", "delSourceGlobField(" + id + ")");
	}
}	


function delSourceGlobField(index) {
	// get the row to remove
	row_node = $("glob_row_" + index);
	row_node.remove();
	initGlobRows();
}


function initGlobRows() {
	var globRows = $$('tr.glob_row');
	// re-number the rows, show the X, and hide the plus
	for (i=0; i < globRows.length; i++) {
		modifyRow(globRows[i], i);
		td = globRows[i].lastChild;
		$(td.childNodes[td.childNodes.length - 1]).hide();
		$(td.childNodes[td.childNodes.length - 2]).show();
	}
	// if THERE'S ONLY ONE globRow ...
	if (globRows.length == 1) {
		// ... hide the X
		td = globRows[0].lastChild;
		$(td.childNodes[td.childNodes.length - 2]).hide();
	}
	// and show the + on the last row
	td = globRows.last().lastChild;
	$(td.childNodes[td.childNodes.length - 1]).show();
}


function addSourceGlobFields() {
	// Get a list of all the glob rows
	globRows = $$('tr.glob_row');
	// make a copy of the last globRow
	lastRow = globRows.last();
	// make the X button visible on this row
	lastRow.lastChild.childNodes[lastRow.lastChild.childNodes.length - 2].show();
	// now create the new row
	newRow = lastRow.cloneNode(true);
	// generate a new id
	newId = parseInt(newRow.id.split("_")[2]) + 1;
	// ...and reset it's attributes
	modifyRow(newRow, newId);
	// and set its content to ''
	newRow.lastChild.childNodes[newRow.lastChild.childNodes.length - 3].value = '';
	if (newRow.lastChild.firstChild.getAttribute('class') == 'errorlist') {
		newRow.lastChild.removeChild(newRow.lastChild.firstChild);
	}
	// add the node
	globRows.last().insert({after: newRow});
	// re-initialise all the fields
	initGlobRows();
}


function jobWindowLoadWrapper(){
	// initialises all the js stuff for hiding and displaying fields as appropriate, as well as sets up the multichoice selectors.
	showSchedule();
	showScripts();
	SelectFilter.init("id_alert_groups_on_success", "Groups", 0, "/media/");
	SelectFilter.init("id_alert_groups_on_fail", "Groups", 0, "/media/");
	AlertOnSuccessField = $($($($($('id_alert_groups_on_success_from').parentNode).parentNode).parentNode).parentNode);
	AlertOnFailField = $($($($($('id_alert_groups_on_fail_from').parentNode).parentNode).parentNode).parentNode);
	var suppressAlertsValue = $("id_suppress_group_alerts").checked;
	if (suppressAlertsValue){
		AlertOnSuccessField.hide()
		AlertOnFailField.hide()
	}
	initGlobRows()
}

function showSuppressGroupAlerts(){
//	SelectFilter.init("id_alert_groups_on_success", "Groups", 0, "/media/");
//	SelectFilter.init("id_alert_groups_on_fail", "Groups", 0, "/media/");
	AlertOnSuccessField = $($($($($('id_alert_groups_on_success_from').parentNode).parentNode).parentNode).parentNode);
	AlertOnFailField = $($($($($('id_alert_groups_on_fail_from').parentNode).parentNode).parentNode).parentNode);

	var suppressAlertsValue = $("id_suppress_group_alerts").checked;
//	alert("suppress alerts is " + suppressAlertsValue);

	if (suppressAlertsValue){
		AlertOnSuccessField.hide()
		AlertOnFailField.hide()
	}
	else{
		AlertOnSuccessField.show()
		AlertOnFailField.show()
	}

}


function showRunOnce(){
	var runOnceValue = $("id_run_once").checked;
	//alert("run once is " + runOnceValue);
	minuteField = $($($('id_minute').parentNode).parentNode);
	hourField = $($($('id_hour').parentNode).parentNode);
	DOMField = $($($('id_day').parentNode).parentNode);
	MonthField = $($($('id_month').parentNode).parentNode);
	DOWField = $($($('id_dow').parentNode).parentNode);
	AdvancedField = $($($('id_advanced').parentNode).parentNode);
	RunAtField = $($($('id_run_at').parentNode).parentNode);
	ScheduleTypeField = $($($('id_schedule_type').parentNode).parentNode);
	if (runOnceValue){
		minuteField.hide();
		hourField.hide();
		DOMField.hide();
		MonthField.hide();
		DOWField.hide();
		AdvancedField.hide();
		ScheduleTypeField.hide();
		ExpiryField.hide();
		RunAtField.show()
	}
	else{
		ScheduleTypeField.show();
		showSchedule();
		ExpiryField.show();
		RunAtField.hide()
	}
}


function showScripts(){
	var preScriptValue = $("id_use_pre_script").checked;
	var postScriptValue = $("id_use_post_script").checked;
	//alert("use pre script is " + preScriptValue + "\n" + "use post script is " + postScriptValue);
	preScriptField = $($($('id_pre_script').parentNode).parentNode);
	postScriptField = $($($('id_post_script').parentNode).parentNode);
	if (preScriptValue){
		preScriptField.show()
	}
	else{
		preScriptField.hide()
	}
	if (postScriptValue){
		postScriptField.show()
	}
	else{
		postScriptField.hide()
	}

}

function showSchedule(){
	// Dynamically changes the addJob form's schedule detail fields according to the selected schedule type
	//var scheduleValue = document.getElementById("id_schedule_type").value;
	var scheduleValue = $("id_schedule_type").value;
	//alert(scheduleValue)
	RunAtField = $($($('id_run_at').parentNode).parentNode);
	minuteField = $($($('id_minute').parentNode).parentNode);
	hourField = $($($('id_hour').parentNode).parentNode);
	DOMField = $($($('id_day').parentNode).parentNode);
	MonthField = $($($('id_month').parentNode).parentNode);
	DOWField = $($($('id_dow').parentNode).parentNode);
	AdvancedField = $($($('id_advanced').parentNode).parentNode);
	ExpiryField = $($($('id_expiry').parentNode).parentNode);
	if(scheduleValue == 0){
		RunAtField.show();
		minuteField.hide();
		hourField.hide();
		DOMField.hide();
		MonthField.hide();
		DOWField.hide();
		AdvancedField.hide();
		ExpiryField.hide();
	}
	else if(scheduleValue == 1){
		//hourly
		RunAtField.hide();
		minuteField.show();
		hourField.hide();
		DOMField.hide();
		MonthField.hide();
		DOWField.hide();
		AdvancedField.hide();
		ExpiryField.show();
	}
	else if(scheduleValue == 2){
		//daily
		RunAtField.hide();
		minuteField.show();
		hourField.show();
		DOMField.hide();
		MonthField.hide();
		DOWField.hide();
		AdvancedField.hide();
		ExpiryField.show();
	}
	else if(scheduleValue == 3){
		//weekly
		RunAtField.hide();
		minuteField.show();
		hourField.show();
		DOMField.hide();
		MonthField.hide();
		DOWField.show();
		AdvancedField.hide();
		ExpiryField.show();
	}
	else if(scheduleValue == 4){
		//monthly
		RunAtField.hide();
		minuteField.show();
		hourField.show();
		DOMField.show();
		MonthField.hide();
		DOWField.hide();
		AdvancedField.hide();
		ExpiryField.show();
	}
	else if(scheduleValue == 5){
		//yearly
		RunAtField.hide();
		minuteField.show();
		hourField.show();
		DOMField.show();
		MonthField.show();
		DOWField.hide();
		AdvancedField.hide();
		ExpiryField.show();
	}

	else if(scheduleValue == 6){
		//advanced
		RunAtField.hide();
		minuteField.hide();
		hourField.hide();
		DOMField.hide();
		MonthField.hide();
		DOWField.hide();
		AdvancedField.show();
		ExpiryField.show();
	}
}


