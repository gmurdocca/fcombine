#!/usr/bin/python
############################################################################
#
# Fcombine - An enterprise grade automounter and file server
# Copyright (C) 2013 George Murdocca
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#############################################################################

from django import template
import cgi

register = template.Library()

@register.simple_tag
def message_class_lookup(message_type):
	'''
	Returns a message class string that corresponds to a particular message type.
	Essentially, the glue that connects the views' method of specifying message type with the templates' method.
	WARNING! This tag will raise an exception if it is given an argument that cannot be looked up in the context. This is always the case for any tags that use register.simple_tag
	'''
	map = {0:"message_info",
		1:"message_warning",
		2:"message_critical",
		3:"message_debug",
		}
	try:
		return map[message_type]
	except KeyError:
		return ""

@register.simple_tag
def duration_string(total_seconds):
	'''Creates a pretty duration string based on the number of seconds passed in'''
	hours = total_seconds / 3600
	minutes = total_seconds % 3600 / 60
	seconds = total_seconds % 3600 % 60
	duration_string = "%s hours, %s minutes and %s seconds" % (hours, minutes, seconds)
	return duration_string


@register.tag
def render_leet_table(parser, token):
	try:
		tagname, leet_table = token.split_contents()
	except ValueError, e:
		raise template.TemplateSyntaxError, "%r tag requires exactly one argument" % token.contents.split()[0]
	return LeetTableNode(leet_table)

class LeetTableNode(template.Node):

	def __init__(self, leet_table):
		self.leet_table = template.Variable(leet_table)

	def render(self, context):
		try:
			leet_table = self.leet_table.resolve(context)
		except template.VariableDoesNotExist:
			return ''
		result = ""
		result += '''
<script type="text/javascript">
function selectall() {
	var selectAllValue = $("id_select_all").checked;
	var allCheckboxes = $$("input.class_checkbox")
	for (i=0;i<allCheckboxes.length;i++){
		if (selectAllValue){
			allCheckboxes[i].checked = true;
		}
		else{
			allCheckboxes[i].checked = false;
		}
	}
}
</script>
'''
		result += "<form method='GET' action='%s' id='leet_table'>\n" % leet_table.action
		if leet_table.filterable:
			result += '''
						<div id='search'>
							<label for='searchbar'>Search: </label>
							<input type='text' name='filter'id='searchbar' value='%(filter)s'>
							<input type='submit' name='button' value='Go'><input type='button' value='Clear' onclick='goToURL("%(action)s")'>
							Showing %(count)s of <a href="%(action)s">%(total)s %(description)ss</a>
						</div>
					  ''' % {'filter':leet_table.filter, 'action':leet_table.action, 'total':leet_table.totalObjects, 'count':len(leet_table.objects), 'description':leet_table.objectDescription}
		result += "<table><thead><tr class='alt'>\n"
		if leet_table.sortable:
			result += '''
<script type="text/javascript">
function sort(col) {
	sortCol = document.getElementById('sortCol');
	if (sortCol.value == col) {
		sortOrder = document.getElementById('sortOrder');
		if (sortOrder.value != 'desc') {
			sortOrder.value = 'desc';
		} else {
			sortOrder.value = 'asc';
		}
	} else {
		document.getElementById('sortCol').value = col;
		document.getElementById('sortOrder').value = 'asc';
	}
	the_form = document.getElementById('leet_table');
	the_form.submit();
}
</script>
'''
		for heading in leet_table.headings:
			result += "<th>"
			if leet_table.sortable and heading[0].sortable:
				col = heading[1]
				text = heading[0].text
				sort_order_icon = ""
				if leet_table.sortCol == col or leet_table.sortCol == "-%s" % col:
					if leet_table.sortOrder == "asc":
						sort_order_icon = ' <img src="/media/xsftp/column_order_down.png" alt="down"/>'
					else:
						sort_order_icon = ' <img src="/media/xsftp/column_order_up.png" alt="up"/>'
				result += "<a href='#' onClick='sort(\"%(col)s\")'>%(text)s%(sort_order_icon)s</a>" % {'col':col, 'text':text, 'sort_order_icon':sort_order_icon}
			elif heading[0].text == "_select_all":
				result += "<input type='checkbox' id='id_select_all' name='select_all' value='select_all' onClick='selectall()' />"
			else:
				result += '%s' % heading[0].text
			result += "</th>\n"
		result += "</tr></thead>\n"
		row_counter = 0
		for object in leet_table.objects:
			# alternate each row's BG colour
			if row_counter % 2 == 0:
				row_style = 'row1'
			else:
				row_style = 'row2'
			row_fg_colour = "black"
			# if we have a line colour formatter:
			if len(object) == 2 and type(object[0]) == type(tuple()):
				row_fg_colour = object[1]
				object = object[0]
			result += "<tr class='%s' style='color:%s'>" % (row_style, row_fg_colour)
			row_counter += 1
			for col in range(len(object)):
				result += "<td>"
				# Work out how to render the data
				render_as = leet_table.headings[col][0].render_as
				if render_as == "boolean":
					if object[col]:
						data = "<img src='/media/xsftp/icon-yes.gif' alt='Yes'>"
					else:
						data = "<img src='/media/xsftp/icon-no.gif' alt='No'>"
				elif render_as == "null_boolean":
					if object[col] == True:
						data = "<img src='/media/xsftp/icon-yes.gif' alt='Yes'>"
					elif object[col] == False:
						data = "<img src='/media/xsftp/icon-no.gif' alt='No'>"
					else:
						data = "N/A"
				elif render_as == "text_boolean":
					if object[col] == True:
						data = "Yes"
					else:
						data = "No"
				elif render_as == "jobstatus":
					if object[col] == None:
						data = "Terminating ..."
					elif object[col]:
						data = "Yes"
					else:
						data = "No"
				elif render_as == "checkbox":
					data = ""
					if int(object[col][1]):
						checked = " CHECKED"
					else:
						checked = ""
					# this is the user table, then omit the checkbox for the builtin admin user.
					if not leet_table.action == "/users/" or (leet_table.action == "/users/" and int(object[col][0] != 1)):
						data = """<input class='class_checkbox' type='checkbox' name='selected' value='%s'%s onClick="$('id_select_all').checked = false" """ % (object[col][0], checked)
				elif render_as == "link":
					data = "<a href='%s'>%s</a>" % (object[col][1], object[col][0])
				elif render_as == "multi_link":
					data = []
					for text, link in object[col]:
						data.append("<a href='%s'>%s</a>" % (link, text))
					data = "<br />".join(data)
				elif render_as == "datetime":
					if object[col]:
						data = object[col].strftime("%Y-%m-%d %H:%M:%S")
					else:
						data = "Never"
				else:	
					data = cgi.escape(str(object[col]))
				result += "%s</td>" % data
			result += "</tr>"
		result += "</table>\n"
		result += "<input type='hidden' id='sortCol' name='sortCol' value=%s>" % leet_table.sortCol
		result += "<input type='hidden' id='sortOrder' name='sortOrder' value=%s>" % leet_table.sortOrder
		for button in leet_table.buttons:
			result += "<input type='submit' name='%s' value='%s'>" % (button.name, button.value)
			# Add in the buttons delimiter, if it has one
			if button.delimiter:
				result += button.delimiter
		result += "</form>"
		return result


