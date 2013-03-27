
function showType(){
	var typeValue = $("id_type").value;
	//alert("Type is " + typeValue);

	ssh_port_field = $($($('id_port').parentNode).parentNode);
	cifs_port_field = $($($('id_cifs_port').parentNode).parentNode);
	cifs_password_field = $($($('id_cifs_password').parentNode).parentNode);
	cifs_share_field = $($($('id_cifs_share').parentNode).parentNode);
	ftp_port_field = $($($('id_ftp_port').parentNode).parentNode);
	ftp_password_field = $($($('id_ftp_password').parentNode).parentNode);
	ftp_passive_field = $($($('id_ftp_passive').parentNode).parentNode);
	ftp_encryption_field = $($($('id_ftp_encryption').parentNode).parentNode);
	remote_user_field = $($('id_remote_user').parentNode);


	if (typeValue == 'sftp'){
		ssh_port_field.show();
		cifs_port_field.hide();
		cifs_password_field.hide();
		cifs_share_field.hide();
		ftp_port_field.hide();
		ftp_password_field.hide();
		ftp_passive_field.hide();
		ftp_encryption_field.hide();
		remote_user_field.innerHTML =  delText(remote_user_field.innerHTML, "To specify a domain, use the format: domain\\username");
	}
	else if (typeValue == 'cifs') {
		ssh_port_field.hide();
		cifs_port_field.show();
		cifs_password_field.show();
		cifs_share_field.show();
		ftp_port_field.hide();
		ftp_password_field.hide();
		ftp_passive_field.hide();
		ftp_encryption_field.hide();
		remote_user_field.innerHTML = addText(remote_user_field.innerHTML, "To specify a domain, use the format: domain\\username");
	}
	else { //typeValue == 'ftp'
		ssh_port_field.hide();
		cifs_port_field.hide();
		cifs_password_field.hide();
		cifs_share_field.hide();
		ftp_port_field.show();
		ftp_password_field.show();
		ftp_passive_field.show();
		ftp_encryption_field.show();
		remote_user_field.innerHTML =  delText(remote_user_field.innerHTML, "To specify a domain, use the format: domain\\username");
	}
}

function delText(html, text){
	var result = html;
	var textIndex = html.indexOf(text);
	if (textIndex > 0){
		result = html.substring(0,textIndex -4);
	}
	return result
}

function addText(html, text){
	var result = html;
	var textIndex = html.indexOf(text);
	if (textIndex == -1){
		result = html + "<BR>" + text;
	}
	return result
}

