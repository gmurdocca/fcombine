// Get all appropriate tags, based on their class
function attachCalendars () {
	dateFields = getElementsByClassName("vDateField");
	dateTimeFields = getElementsByClassName("vDateTimeField");
	basicDateTimeFields = getElementsByClassName("vBasicDateTimeField");

	// process Date Fields
	for (i = 0, j = dateFields.length; i < j; i++) {
		// create a new image to make into a button, give it a uique ID
		var calImage = document.createElement('img');
		calImage.setAttribute('src', '/media/xsftp/icon_calendar.png');
		//calImage.setAttribute('width','22px');
		calImage.setAttribute('style','vertical-align:middle');
		calImage.setAttribute('title','Date selector');
		// create a new anchor to wrap around the image
		var calAnchor = document.createElement('a');
		calAnchor.appendChild(calImage);
		calAnchor.setAttribute('href', '#');
		calAnchor.setAttribute('id', 'triggerD' + i);
		// create a "Clear the date" anchor
		var clearAnchor = document.createElement('a');
		clearAnchor.appendChild(document.createTextNode(" Never"));
		clearAnchor.setAttribute('href', '#');
		clearAnchor.setAttribute('onclick', 'document.getElementById(\'' + dateFields[i].id + '\').value=\'\'');
		// create a text note " | " to split the clear and calendor anchors
		var separator = document.createTextNode(" | ")
		// Add the 3 new elements to the appropriate field
		dateFields[i].parentNode.appendChild(clearAnchor);
		dateFields[i].parentNode.appendChild(separator);
		dateFields[i].parentNode.appendChild(calAnchor);
		dateFields[i].setAttribute('style', 'vertical-align: middle');
		// Now create the actual calendar object
		Calendar.setup(
			{
				inputField  : dateFields[i].id,         // ID of the input field
				ifFormat    : "%Y-%m-%d",    // the date format
				button      : calAnchor.id,       // ID of the button
				//showsTime	: 1
				range		: [2006, 2999]
			}
		);
	}

	// process DateTime Fields
	for (i = 0, j = dateTimeFields.length; i < j; i++) {
		// create a new image to make into a button, give it a unique ID
		var calImage = document.createElement('img');
		calImage.setAttribute('src', '/media/xsftp/icon_calendar.png');
		calImage.setAttribute('style','vertical-align:middle');
		calImage.setAttribute('title','Date and Time selector');
		// create a new anchor to wrap around the image
		var calAnchor = document.createElement('a');
		calAnchor.appendChild(calImage);
		calAnchor.setAttribute('href', '#');
		calAnchor.setAttribute('id', 'triggerDT' + i);
		// create a "Clear the date" anchor
		var clearAnchor = document.createElement('a');
		clearAnchor.appendChild(document.createTextNode(" Never"));
		clearAnchor.setAttribute('href', '#');
		clearAnchor.setAttribute('onclick', 'document.getElementById(\'' + dateTimeFields[i].id + '\').value=\'\'');
		// create a text note " | " to split the clear and calendor anchors
		var separator = document.createTextNode(" | ")
		// Add the 3 new elements to the appropriate field
		dateTimeFields[i].parentNode.appendChild(clearAnchor);
		dateTimeFields[i].parentNode.appendChild(separator);
		dateTimeFields[i].parentNode.appendChild(calAnchor);
		dateTimeFields[i].setAttribute('style', 'vertical-align: middle');
		// Now create the actual calendar object
		Calendar.setup(
			{
				inputField  : dateTimeFields[i].id,         // ID of the input field
				ifFormat    : "%Y-%m-%d %H:%M",    // the date format
				button      : calAnchor.id,       // ID of the button
				showsTime	: true,
				range		: [2006, 2999]
			}
		);
	}

	// process BasicDateTime Fields
	for (i = 0, j = basicDateTimeFields.length; i < j; i++) {
		// create a new image to make into a button, give it a unique ID
		var calImage = document.createElement('img');
		calImage.setAttribute('src', '/media/xsftp/icon_calendar.png');
		calImage.setAttribute('style','vertical-align:middle');
		calImage.setAttribute('title','Date and Time selector');
		// create a new anchor to wrap around the image
		var calAnchor = document.createElement('a');
		calAnchor.appendChild(calImage);
		calAnchor.setAttribute('href', '#');
		calAnchor.setAttribute('id', 'triggerBDT' + i);
		// Add the new element to the appropriate field
		//basicDateTimeFields[i].parentNode.appendChild(calAnchor);
        basicDateTimeFields[i].parentNode.insertBefore(calAnchor, basicDateTimeFields[i].nextSibling)
		basicDateTimeFields[i].setAttribute('style', 'vertical-align: middle');
		// Now create the actual calendar object
		Calendar.setup(
			{
				inputField  : basicDateTimeFields[i].id,         // ID of the input field
				ifFormat    : "%Y-%m-%d %H:%M",    // the date format
				button      : calAnchor.id,       // ID of the button
				showsTime	: true,
				range		: [2006, 2999]
			}
		);
	}

}

//Register the event upon which the above is run
addEvent(window, "load", attachCalendars);


