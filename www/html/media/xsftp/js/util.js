function addEvent(obj, evType, fn) {
	if (obj.addEventListener) {
		obj.addEventListener(evType, fn, false);
		return true;
	} else if (obj.attachEvent) {
		var r = obj.attachEvent("on" + evType, fn);
		return r;
	} else {
		return false;
	}
}

function getElementsByClassName(className, tag, elm){
	var testClass = new RegExp("(^|\\\\s)" + className + "(\\\\s|$)");
	var tag = tag || "*";
	var elm = elm || document;
	var elements = (tag == "*" && elm.all)? elm.all : elm.getElementsByTagName(tag);
	var current;
	var length = elements.length;
	var returnElements = []
	for(var i=0; i<length; i++){
		current = elements[i];
		if(testClass.test(current.className)){
			returnElements.push(current);
		}
	}
	return returnElements;
}


function get_viewport_dimensions(){
	var viewportwidth;
	var viewportheight;
	// the more standards compliant browsers (mozilla/netscape/opera/IE7) use window.innerWidth and window.innerHeight
	if (typeof window.innerWidth != 'undefined') {
		viewportwidth = window.innerWidth,
		viewportheight = window.innerHeight
	}
	// IE6 in standards compliant mode (i.e. with a valid doctype as the first line in the document)
	else if (typeof document.documentElement != 'undefined' && typeof document.documentElement.clientWidth !='undefined' && document.documentElement.clientWidth != 0) {
		viewportwidth = document.documentElement.clientWidth,
		viewportheight = document.documentElement.clientHeight
	}
	// older versions of IE
	 else {
		viewportwidth = document.getElementsByTagName('body')[0].clientWidth,
		viewportheight = document.getElementsByTagName('body')[0].clientHeight
	}
	return [viewportwidth, viewportheight];
}


function getDocHeight() {
    var D = document;
    return Math.max(
        Math.max(D.body.scrollHeight, D.documentElement.scrollHeight),
        Math.max(D.body.offsetHeight, D.documentElement.offsetHeight),
        Math.max(D.body.clientHeight, D.documentElement.clientHeight)
    );
}


function autoHeight(){
	// initialise required values
	viewPortHeight = get_viewport_dimensions()[1];
	viewport_autoheight_elements = $$('.autoheight_vp');
	footer_height = $('footer').getHeight() + 2;
	nav_height = $('normalnav').getHeight();
	header_height = $('nav').cumulativeOffset()[1];
	if ($('adminnav') != null) {
		nav_height += $('adminnav').getHeight();
	}
	bottom_of_nav = header_height + nav_height;
	// set height of .autoheight_vp elements (eg. the syslog div)
	for (i = 0; i < viewport_autoheight_elements.length; i++){
		autoheight_element = viewport_autoheight_elements[i];
		offset = autoheight_element.cumulativeOffset();
		offset = offset[1] + footer_height;
		new_height = viewPortHeight - offset;
		if ((new_height + offset) < bottom_of_nav + footer_height){
			new_height = bottom_of_nav + footer_height - offset;
		}
		autoheight_element.style.height = String(new_height) + 'px';
	}
	// ensure body is the same height as nav
	body_element = $('body');
	if (body_element.getHeight() < nav_height) {
		body_element.style.height = String(nav_height) + 'px';
	}
	// ensure explorer divs are correct height
	explorer_pane_elements = $$('div.explorer');
	if (explorer_pane_elements.length != 0) {
		// set heights
		min_height = 400;
		top_of_explorer_lhs = $('explorer_lhs').cumulativeOffset()[1];
		top_of_explorer_rhs = $('explorer_rhs').cumulativeOffset()[1];
		if (top_of_explorer_lhs < top_of_explorer_rhs) {
			top_offset = top_of_explorer_lhs;
		}
		else {
			top_offset = top_of_explorer_rhs;
		}

		offset = top_offset + $('explorer_bottom').getHeight() + footer_height + 12;
		correct_height = viewPortHeight - offset;
		if ( correct_height < min_height ) {
			correct_height = min_height;
		}
		for (i = 0; i < explorer_pane_elements.length; i++){
			explorer_pane_element = explorer_pane_elements[i];
			explorer_pane_element.style.height = String(correct_height) + 'px';
			// if the explorer pane is longer than its correct height, add right-padding to prevent scrollbar overlap
			if (explorer_pane_element.getHeight() < explorer_pane_element.scrollHeight) {
				explorer_pane_element.style.paddingRight = '15px';
			}
			// set correct explorer pane width
			explorer_pane_element.style.width = explorer_pane_element.scrollWidth;
		}
		// ensure the body height is correct
		correct_body_height = $('footer').cumulativeOffset()[1] - header_height - 2;
		body_element.style.height = String(correct_body_height) + 'px';
	}
	// ensure nav is full height
	correct_nav_height = $('footer').cumulativeOffset()[1] - header_height;
	if (nav_height < correct_nav_height) {
		$('nav').style.height = String(correct_nav_height) + 'px';
	}
}


