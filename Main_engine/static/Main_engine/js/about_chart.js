for(var i=0; i<=4; i++){
var id_str = "mychart" + i;
  var ctx = document.getElementById(id_str).getContext('2d');
  id_str = new Chart(ctx, {
      type: 'bar',
      data: {
          labels: ['bbh', 'cg', '상수', 'pe'],
          datasets: [{
              label: '# 유사도',
              data: [80,40,30,20],
              backgroundColor: [
                  'rgba(255, 99, 132, 0.2)',
                  'rgba(54, 162, 235, 0.2)',
                  'rgba(255, 206, 86, 0.2)',
                  'rgba(75, 192, 192, 0.2)',
                  'rgba(153, 102, 255, 0.2)',
                  'rgba(255, 159, 64, 0.2)'
              ],
              borderColor: [
                  'rgba(255, 99, 132, 1)',
                  'rgba(54, 162, 235, 1)',
                  'rgba(255, 206, 86, 1)',
                  'rgba(75, 192, 192, 1)',
                  'rgba(153, 102, 255, 1)',
                  'rgba(255, 159, 64, 1)'
              ],
              borderWidth: 1
          }]
      },
      options: {
              responsive: false,
              scales: {
yAxes: [{
  barPercentage: 0.5,
  gridLines: {
    display: false
  },
  ticks: {
    min: 0,
    max: 100,
    stepSize: 10
  },
}],
}
      }
  });
}
/* 엔진에서 받아온 값 */
var result = "{{result}}";
/* JSON.parse()에서 따옴표 있으면 오류남 */
var text_res = result.replace(/&#39;/gi, '"');
/* 결과값 파싱해서 테이블 추가하는 부분 */
/* 테이블 불러오기 */
var res_table = document.getElementById("result_table");
/* 결과 데이터 파싱 */
var json_res = JSON.parse(text_res);
/* 기준 파일을 선택할 select 태그 생성
var select_file = document.createElement("SELECT");
select_file.id = "standard_file";
document.select_form.appendChild(select_file);
*/
var select_file = document.getElementById("select_file");
for (var standard in json_res) {
    var option = document.createElement("option");
    option.value = standard;
    option.text = standard;
    select_file.appendChild(option);
}
select_file.selectedIndex = 0;
/* 기준이 변하면 테이블이 변경될 수 있도록 */
function change_table() {
    /* 기준이 변할때마다 테이블을 지우고 새로 시작 */
    for (var row = res_table.rows.length - 1; row > 1; row--) {
        res_table.deleteRow(row);
    }
    for (var standard in json_res) {
        /*document.write("standard is " + standard +"<br>");*/
        var sel = document.getElementById("select_file");
        if (standard == sel.options[sel.selectedIndex].value) {
            /* 대상이 변할때마다 */
            for (var target in json_res[standard]) {
                /*document.write("target is " + target + "<br>");*/
                /*document.write(json_res[standard][target]+ "<br>");*/
                /* 하단에 행 추가 */
                var new_row = res_table.insertRow(res_table.rows.length);
                /* 행에 열 추가 */
                var filename = new_row.insertCell(0);
                //var timestamp = new_row.insertCell(1);
                var bbh = new_row.insertCell(1);
                var constvalue = new_row.insertCell(2);
                var section = new_row.insertCell(3);
                var cert = new_row.insertCell(4);
                var pdb = new_row.insertCell(5);
                var imph = new_row.insertCell(6);
                var xor = new_row.insertCell(7);
                /* 열에 데이터 입력 */
                filename.innerHTML = json_res[standard][target][0];
                bbh.innerHTML = json_res[standard][target][1];
                constvalue.innerHTML = json_res[standard][target][2];
                section.innerHTML = json_res[standard][target][3];
                cert.innerHTML = json_res[standard][target][4];
                pdb.innerHTML = json_res[standard][target][5];
                imph.innerHTML = json_res[standard][target][6];
                xor.innerHTML = json_res[standard][target][7];
            }
        }
    }
}
change_table();

