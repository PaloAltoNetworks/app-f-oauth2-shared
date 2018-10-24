
$(() => {
    let p1 = $("#pw1");
    let p2 = $("#pw2");
    let l = window.location.pathname;
    $("#loginform").attr("action", l + window.location.search);
    $("#createform").attr("action", l + '/create' + window.location.search);
    p2.change(event => {
        if (p1.val() != p2.val()) {
            p2.addClass('bg-warning');
        } else {
            p2.removeClass('bg-warning');
        }
    });
    $("#cb").click(event => {
        if (p1.val() != p2.val()) {
            event.preventDefault();
        }
    })
    let vars: { [index: string]: string } = {}, hash: string[] = [];
    let q = window.location.search.split('?')[1];
    if (q != undefined) {
        let p: string[] = q.split('&');
        for (var i = 0; i < p.length; i++) {
            hash = p[i].split('=');
            vars[hash[0]] = decodeURIComponent(hash[1]);
        }
    }
    if ("err" in vars) {
        $("#alert").text(vars['err']).removeClass("invisible");
    }
});
