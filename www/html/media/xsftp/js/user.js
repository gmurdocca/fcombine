
function showPasswordFields(){
	var internalAuthValue = $("id_internal_auth").checked;
	/* alert("Local Account is " + internalAuthValue); */
	passwordField = $($($('id_password_1').parentNode).parentNode);
	verifyPasswordField = $($($('id_password_2').parentNode).parentNode);
	if (internalAuthValue){
		passwordField.show()
		verifyPasswordField.show()
	}
	else{
		passwordField.hide()
		verifyPasswordField.hide()
	}
}

