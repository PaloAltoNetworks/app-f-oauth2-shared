declare class Vue {
    constructor(e: object);
};

let db: oa2sc;

$(() => {
    let baseUrl = window.location.href.split('?')[0];
    if (baseUrl[baseUrl.length - 1] != '/') {
        baseUrl += '/';
    }
    oa2sc.getOa2sc(baseUrl).then(d => {
        if (d == null) {
            return;
        }
        db = d;
        let ctoken = "";
        var app = new Vue({
            el: '#app',
            data: {
                d: db,
                copytoken: ctoken
            },
            methods: {
                delToken: function (i: number, t: number): void {
                    (this.d as oa2sc).removeToken(i, t).catch(
                        function (e: JQueryXHR) { console.log("ERROR - %s", e.responseText) });
                },
                revokeToken: function (i: number, t: number): void {
                    (this.d as oa2sc).revokeToken(i, t).catch(
                        function (e: JQueryXHR) { console.log("ERROR - %s", e.responseText) });
                },
                addToken: function (i: number, subject: string, radio: string): void {
                    let val = $(`input[name="${radio}"]:checked`).val();
                    if (val == undefined || typeof val != 'string') {
                        console.log("ERROR - undefined/invalid value");
                        return;
                    }
                    let valN = parseInt(val);
                    if (valN === NaN) {
                        console.log("ERROR - value is not a number");
                        return;
                    }
                    let sub = $(`#${subject}`);
                    let subVal = sub.val();
                    if (subVal == undefined || typeof subVal != 'string' || subVal == '') {
                        subVal = "_default_";
                    }
                    (this.d as oa2sc).addToken(i, subVal, valN).then(
                        function (s: string) {
                            console.log("INFO - Created Token %s", s);
                            sub.val('');
                        }).catch(
                            function (e: JQueryXHR) { console.log("ERROR - %s", e.responseText) });;
                },
                delInstance: function (i: number): void {
                    (this.d as oa2sc).removeInstance(i).catch(
                        function (e: JQueryXHR) { console.log("ERROR - %s", e.responseText) });
                },
                activateInstance: function (i: number): void {
                    if (!((this.d as oa2sc).instances[i].activated)) {
                        window.location.href = (this.d as oa2sc).url + `db/instance/activate?instance=${(this.d as oa2sc).instances[i].uuid}`;
                    }
                },
                copyToken: function (modId: string, value: string): void {
                    (this.copytoken as string) = value;
                    ($(`#${modId}`) as any).modal('show');
                }
            }
        })
    }).catch(e => {
        console.log(e);
    });
    $("#logoutform").attr("action", baseUrl + 'logout');
});
