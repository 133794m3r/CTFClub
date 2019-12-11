/**
 *
 * Copyright: 2011 by Macarthur Inbody, Licensed under the LGPL v3 or higher
 * Javascript SQL query parser.
 *
 */

/**
 *Haystack Searcher
 *
 *checks a string for all occurences of a value AND returns all of them.
 *
 *@param    needle str     the value to be searched for
 *@param    limit int     the limit to the values found
 *@return   mixed   array or integer relaying the values AND where it is found.
*/
String.prototype.haystack=function(needle,limit){
	var length =this.length;
	var i=0;
	var strp='';
        var matchval=0;
	var matches=new Array;
        var needlen=needle.length;
	if(limit===undefined){
		limit=0;
	}
	for(i=0;i<=length;++i){
		strp=this.substr(i,needlen);
                matchval=strp.search(needle);
		if(matchval!==-1){
		    matches.push(i);
		}
                if(i===limit&&limit===1){
                    return matches;
                }
	}
	return matches;
}

function rand_str(length){
    var i=0;
    var string='';
    for(i=0;i<length;++i){
        string+=chr(rand(32,126));
    }
    return string;
}

/**
 *
 *  All Indexes
 *
 *  Finds all instances of an item in an array
 *
 *  @variable {array}     array           the array to be searched
 *  @param  {string}    search_string   the regex to find the item
 *  @param  {integer}   limit           the optional limit
 *  @return {mixed}                     -1 if not found, an array if items are found.
 */
Array.prototype.index_all=function (search_string,limit){
    var i=0,c=0;
    var found_array=new Array();
    if(limit===undefined){
        limit=this.length;
    }
    while(i!==-1&&(limit!==0)){
        i=this.indexOf(search_string,i+1);
        ++c;
        if(i!==-1){
            found_array.push(i);
        }
        --limit;
    }
    if(found_array.length!==0){
        return found_array;
    }
    else{
        return -1;
    }
}

Array.prototype.index=function(search_string){
    return this.indexOf(search_string);
}

function arr_string_index(search_array,search_string,from_index){
    var complete_array=new Array();
    var tmp,tmp2,tmp3,i;
    var search_array_length=search_array.length;
    if(from_index!==undefined){
        i=tmp3;
    }
    else{
        i=0;
    }
    tmp=search_array.indexOf(search_string);
    if(tmp===-1){
        for(;i<=search_array_length;++i){
            tmp2=search_array[i].indexOf(search_string);
            if(tmp2!==-1){
                complete_array.push(i);
                complete_array.push(tmp2);
            }
        }
    }
    if(complete_array.length!==0){
        tmp3=complete_array;
    }
    else{
        tmp3=-1;
    }
    return tmp3;
}

function index(search_from,search_string){
    return this.indexOf(search_string);
}
function index_all(search_from,search_string){
    var i=0,c=0;
    var found_array=new Array();
    if(limit===undefined){
        limit=this.length;
    }
    while(i!==-1&&(limit!==0)){
        i=this.indexOf(search_string,i+1);
        ++c;
        if(i!==-1){
            found_array.push(i);
        }
        --limit;
    }
    if(found_array.length!==0){
        return found_array;
    }
    else{
        return -1;
    }
}
