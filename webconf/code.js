var pages = new Array( "login", "admin", "main", "loading", "error", "ident", "mp", "stats", "start" );
var p2pship_config = false;
var host;
var port;
var jsload = 0;

/* urldecoder */
function urldecode(str)
{
    return unescape(str.replace(/\+/g, " "));
}

/* utility funcs */
function get_host_http_prefix()
{
    if (!port || !host)
        return "";
    else
        return "http://" + host + ":" + port;
}

function get_host_get_params()
{
    if (!port || !host)
        return "";
    else
        return "host="+host+"&port="+port;
}

function gup(name)
{
    name = name.replace(/[\[]/,"\\\[").replace(/[\]]/,"\\\]");
    var regexS = "[\\?&]"+name+"=([^&#]*)";
    var regex = new RegExp( regexS );
    var results = regex.exec( window.location.href );
    if( results == null )
        return false;
    else
        return results[1];
}

function showerror(msg) {
    settext("error_msg", msg);
    showpage("error");
}

function setdisplay(e, val) {
    e.style.display = val;
}

function showpage(name) {
    for (var i=0; i < pages.length; i++) {
        if (pages[i] != name)
            setdisplay(document.getElementById("page_" + pages[i]), "none");
    }

    var pe = document.getElementById("page_" + name);
    if (pe)
        setdisplay(pe, "");
    else
        showerror("Internal error, tried to load page " + name);

    if (name != "error" && name != "login") {
        setdisplay(document.getElementById("div_links"), "");
        document.getElementById("links_sys").href = "?page=main&" + get_host_get_params();
        document.getElementById("links_ident").href = "?page=ident&" + get_host_get_params();
        document.getElementById("links_mp").href = "?page=mp&" + get_host_get_params();
        document.getElementById("links_stats").href = "?page=stats&" + get_host_get_params();
        document.getElementById("links_admin").href = "?page=admin&" + get_host_get_params();
        document.getElementById("links_shutdown").href = get_host_http_prefix() + "/shutdown?return_url=" + escape(window.location.href);
        document.getElementById("links_restarthipd").href = get_host_http_prefix() + "/restarthipd?return_url=" + escape(window.location.href);
    }
}
function openpage(url) {
    document.location = url;
}

function printd(text) {
    document.getElementById("debug").value += text + "\n";
}
function cleard() {
    document.getElementById("debug").value = "";
}

function settext(elmname, msg) {
    document.getElementById(elmname).textContent = msg;
}
	
/* init */
function initpage(page_name) {
    cleard();

    if (window.location.href.indexOf("file://") == 0) {
        port = gup("port");
        host = gup("host");
        if (!port || !host)
            return showpage("login");
        load_config();
    } else {
        jsload = 0;
        initpage2();
    }
}

function setinputvalue(page_name, inputname, val) {
    var e = document.getElementById(page_name + "_" + inputname);
    if (e) {
        e.value = val;
    }
}

/* submits & reloads a page */
function submit_reload(formname) {
    if (window.location.href.indexOf("file://") == 0) {
        document.getElementById(formname).submit();
        //setTimeout("submit_reload2()", 500);
        submit_reload2();
    } else {
        var inp = document.createElement("input");
        inp.type = "hidden";
        inp.name = "return_url";
        inp.value = window.location.href;
        document.getElementById(formname).appendChild(inp);
        document.getElementById(formname).submit();
    }
}


function submit_reload2() {
    window.location.reload();
}

function tdigs(str) {
    str = "" + str;
    while (str.length < 2)
        str = "0" + str;
    return str;
}

/* date to string */
function datetostr(str) {
    var d = new Date();
    d.setTime(str + "000");
    return d.getDate() + "." + (d.getMonth()+1) + "." + d.getFullYear() + "&nbsp;" + d.getHours() + ":" + tdigs(d.getMinutes()) + ":" + tdigs(d.getSeconds());
}

/* date to string */
function datediff(str) {
    var d = new Date();
    var diff = ((d.getTime() - (str + "000")) / 1000);
    if (diff < 60)
        return diff + " secs";
    else if (diff < (60*60))
        return Math.floor(diff/60) + " min, "+Math.floor(diff%60)+" s";
    else
        return Math.floor(diff/(60*60))+ "h, " + Math.floor((diff%(60*60))/60)+" min, "+Math.floor(diff%60)+" s";
}

/* adds an element to the given form */
function add_input(formname, elmname, elmvalue)
{
    var form = document.getElementById(formname);
    var inp = document.createElement("input");
    inp.type = "hidden";
    inp.name = elmname;
    inp.value = elmvalue;
    form.appendChild(inp);
}

function add_td(tr, content) 
{
	td = document.createElement("td");
	tr.appendChild(td);
	td.innerHTML = content;
	return td;
}

function d2(i) {
        if (i < 10)
                return "0" + i;
        return i;
}

function format_time(time) {
  var mons = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' ];
  d = new Date(time*1000);
  return d.getDate() + " " + mons[d.getMonth()] + " " + d.getFullYear() +  " " + d2(d.getHours()) + ":" + d2(d.getMinutes());
}

/* finishes the initialization after the config has been loaded */
function initpage2() {

    if (!p2pship_config && jsload < 15) {
        jsload++;
        setTimeout("initpage2()", 100);
        return;
    }
    
    if (!p2pship_config)
        return showerror("Couldn't load the config");
    
    /* common stuff */
    var ut = p2pship_info["uptime"];
  var ut_d = 0;
  if (ut > (60*60*24)) {
    ut_d = Math.floor((ut/(60*60*24)));
    ut = ut - (ut_d * 60*60*24);
  }
  var ut_h = 0;
  if (ut > (60*60)) {
    ut_h = Math.floor((ut/(60*60)));
    ut = ut - (ut_h * 60*60);
  }
  
    document.getElementById("div_info").innerHTML = "Uptime: " 
        + ut_d + "d, "
        + ut_h + "h "
        + Math.floor((ut/(60))) + "m "
        + Math.floor((ut%(60))) + "s.";

    if (p2pship_info["locks"] > 0 || p2pship_info["waits"] > 0) {
        document.getElementById("div_info").innerHTML += 
            " <font color=red>Currently held are " + p2pship_info["locks"] + " locks and " + p2pship_info["waits"] + " waits</font>";
    }

    var page = gup("page");
    if (page == "main") {

        var table = document.getElementById("main_conftable");
        var sub = document.getElementById("main_conftable_buttons"); //table.childNodes[1];

        var form = document.getElementById("main_confform");
        form.action = get_host_http_prefix() + "/post/config";

        for (key in p2pship_config) {
            var tr = document.createElement("tr");
            var td = document.createElement("td");
            var displayrestart = true;
            tr.appendChild(td);
            td.innerHTML = p2pship_config[key][1];
            
            td = document.createElement("td");
            tr.appendChild(td);
            
            if (p2pship_config[key][2] == "bool") {
                var inp = document.createElement("select");
                inp.name = key;
                inp.options[0] = new Option("Yes", "yes");
                inp.options[1] = new Option("No", "no");
                if (p2pship_config[key][0] == "no")
                    inp.options[1].selected = 1;
                td.appendChild(inp);

            } else if (p2pship_config[key][2].substring(0,5) == "enum:") {

                /* parse the options! */
                var ops = p2pship_config[key][2].substring(5).split(",");
                var inp = document.createElement("select");
                inp.name = key;
                
                for (var o = 0; o < ops.length; o++) {
                    var pretty = ops[o];
                    pretty = pretty.substring(0, 1).toUpperCase() + pretty.substring(1);
                    inp.options[o] = new Option(pretty, ops[o]);
                    if (p2pship_config[key][0] == ops[o])
                        inp.options[o].selected = 1;
                }
                td.appendChild(inp);
            } else if (p2pship_config[key][2] == "int" || p2pship_config[key][2] == "string" || p2pship_config[key][2] == "file") {
                var inp = document.createElement("input");
                inp.type = "text";
                inp.name = key;
                inp.value = p2pship_config[key][0];
                td.appendChild(inp);
            } else {
                td.innerHTML = p2pship_config[key][0];
                displayrestart = false;
            }
            
            td = document.createElement("td");
            tr.appendChild(td);
            if (!displayrestart || p2pship_config[key][3] != "dynamic") {
                td.innerHTML = "";
            } else {
                td.innerHTML = "<i>(Restart&nbsp;required)</i>";
            }

            table.insertBefore(tr, sub);
        }
    } else if (page == "ident") {
        /* set form targets */
        document.getElementById("ident_fileform").action = get_host_http_prefix() + "/post/ident_import";
        document.getElementById("ident_syncform").action = get_host_http_prefix() + "/post/save_idents";
        document.getElementById("ident_reloadform").action = get_host_http_prefix() + "/post/reload_idents";

        /* idents */
        var table = document.getElementById("ident_table");
        var i;
        for (sip in p2pship_idents) {
            var tr = document.createElement("tr");
            var reglink = "/reg?local=" + sip;
	    add_td(tr, (p2pship_idents[sip][4] != ""? 
			"<b>" + sip + "</b>":
			sip));
	    
	    /* name */
	    add_td(tr, p2pship_idents[sip][0]);

	    /* online? */
	    add_td(tr, (p2pship_idents[sip][1] == "online"? 
			"<font class=online><a class=online href='"+reglink+"'>" + p2pship_idents[sip][1] + "</a></font>":
			"<font class=offline>" + p2pship_idents[sip][1] + "</font>"));

	    /* deleted etc? */
            add_td(tr, (p2pship_idents[sip][2] != "deleted"? 
			"<form method=\"post\" action=\"" + get_host_http_prefix() + "/post/remove_ident\" "+ "id=\"ident_remove_" + sip + "\">" 
			+ "<input type=\"hidden\" name=\"sip_aor\" value=\""+sip+"\">"
			+ "<input type=\"button\" value=\"Remove\" onClick=\"submit_reload('ident_remove_" + sip + "');\">"
			+ "</form>":
			"<font color='red'>removed</font>"));

	    /* status etc */
            add_td(tr, "<form method=\"post\" action=\"" + get_host_http_prefix() + "/post/set_status\" "+ "id=\"ident_status_" + sip + "\">" 
		   + "<input type=\"hidden\" name=\"sip_aor\" value=\""+sip+"\">"
		   + "<input type=\"text\" name=\"status\" value=\""+urldecode(p2pship_idents[sip][3])+"\">&nbsp;"
		   + "<input type=\"button\" value=\"Set status\" onClick=\"submit_reload('ident_status_" + sip + "');\">"
		   + "</form>");

	    /* default? */
	    add_td(tr, urldecode(p2pship_idents[sip][4]));
            table.appendChild(tr);
	    
            tr = document.createElement("tr");
	    add_td(tr, "");

	    var sstr = "<table><tbody>";
	    //sstr += "<tr><th>Service<th>Registered<th>Contact</tr>";
	    for (service in p2pship_idents[sip][5]) {
		    var selm = p2pship_idents[sip][5][service].split(',');
		    if (selm.length == 5) {
			    selm[1] = parseInt(selm[1]);
			    sstr += "<tr><td>" + selm[0] + " (" + selm[1] + ":" + ((selm[1] >> 16) & 0xffff) + "/" + (selm[1] & 0xffff) + ")</td>";
			    sstr += "<td>" + format_time(selm[2]) + " for " + (selm[3] < 0? "forever":selm[3]+"s") + "</td>";
			    sstr += "<td>" + selm[4] + "</td></tr>";
		    }
	    }
	    sstr += "</tbody></table>";
	    var td = add_td(tr, sstr);
	    td.colSpan = "5";
	    
            table.appendChild(tr);
        }

        /* cas */
        table = document.getElementById("ca_table");
        for (var can = 0; can < p2pship_cas.length; can++) {
            var tr = document.createElement("tr");
            var td = document.createElement("td");
            tr.appendChild(td);
            td.innerHTML = p2pship_cas[can][0];
            
            td = document.createElement("td");
            tr.appendChild(td);
            td.innerHTML = p2pship_cas[can][1];

            table.appendChild(tr);
        }

        /* remote */
        table = document.getElementById("remote_table");
        for (sip in p2pship_remote_regs) {
            var tr = document.createElement("tr");

            var reglink = "/reg?remote=" + sip;
	    /* add_td(tr, "<a href='"+reglink+"'>"+ p2pship_remote_regs[sip][0] + "</a>"); */
	    add_td(tr, p2pship_remote_regs[sip][0]);
	    add_td(tr, "<a href='"+reglink+"'>"+ sip + "</a>");
	    add_td(tr, format_time(p2pship_remote_regs[sip][1]));
	    add_td(tr, format_time(p2pship_remote_regs[sip][2]));
	    add_td(tr, format_time(p2pship_remote_regs[sip][3]));

            table.appendChild(tr);
        }
        
    } else if (page == "mp") {

        /* idents */
        var table = document.getElementById("mp_table");
        for (callid in p2pship_mps) {
            var mp = p2pship_mps[callid][0];
            var tr = document.createElement("tr");
            var td = document.createElement("td");
            var str = "";

            str += "Call <b>" + callid + "</b> (" + mp[0] + " to " + mp[2] + ")";
            td.innerHTML = str;
            tr.appendChild(td);
            table.appendChild(tr);

            tr = document.createElement("tr");
            str = "<td><table><tr>" + 
                "<td>&nbsp;&nbsp;" +
                "</td><td class=thead>From</td>" +
                "<td class=thead>To</td>" +
                "<td class=thead>Type</td>" +
                "<td class=thead>Started</td>" +
                "<td class=thead>Last</td>" +
                "<td class=thead>Bytes</td>" +
                "</tr>";
            
            for (var can = 0; can < p2pship_mps[callid].length; can++) {
                mp = p2pship_mps[callid][can];
                str +=
                    "<tr><td></td><td>"+mp[1]+"</td>" +
                    "<td>"+mp[3]+"</td>" +
                    "<td>"+mp[6]+" ("+mp[4]+")</td>";
                
                if (mp[7] == "1") {
                    str += "<td>"+datetostr(mp[8])+"</td>" +
                    "<td>"+datediff(mp[9])+"</td>" +
                    "<td>"+mp[10]+"</td>" +
                    "</tr>";
                } else {
                    str += "<td>Not started</td><td></td><td></td>";
                }
            }
            str += "</table></td>";
            tr.innerHTML = str;
            table.appendChild(tr);
        }
    } else if (page == "admin") {

    } else if (page == "stats") {

        var table = document.getElementById("stats_table");
        for (var p = p2pship_pdds.length-1; p > -1 ; p--) {
            var pdd = p2pship_pdds[p];
            var tr = document.createElement("tr");

            var td = document.createElement("td");
            td.innerHTML = datetostr(pdd[3]);
            tr.appendChild(td);

            td = document.createElement("td");
            td.innerHTML = pdd[2];
            tr.appendChild(td);

            td = document.createElement("td");
            td.innerHTML = pdd[0];
            tr.appendChild(td);

            td = document.createElement("td");
            td.innerHTML = pdd[1];
            tr.appendChild(td);

            td = document.createElement("td");

            td.innerHTML = "" + (pdd[4] / 1000) + "s. (" + (pdd[5] / 1000) + "s. / " + (pdd[6] / 1000) + "s. / " + (pdd[7] / 1000) + "s. / " + (pdd[8] / 1000) + "s. / " + ((pdd[4]-pdd[5]-pdd[6]-pdd[7]-pdd[8]) / 1000) + "s.)";

            tr.appendChild(td);

            table.appendChild(tr);
        }
    } else {
        page = "start";
    }
    
    showpage(page);
}

function load_config() {

    var pe = document.getElementById("page_loading");
    if (pe)
        setdisplay(pe, "");

    var fileref = document.createElement('script');
    fileref.setAttribute("type","text/javascript");
    fileref.setAttribute("src", get_host_http_prefix() + "/json/all");
    document.getElementsByTagName("head")[0].appendChild(fileref);
    jsload = 0;
    initpage2();
}
