function show_hide(id){
	var element=select_by_id(id);
	var hidden=element.style.display;
	if(hidden === ""){
		element.style.display="none";
	}
	else{
		element.style.display='';
	}
	return 0;
}
function select_by_id(element_id){
	var element=document.getElementById(element_id);
	
	return element;
}
