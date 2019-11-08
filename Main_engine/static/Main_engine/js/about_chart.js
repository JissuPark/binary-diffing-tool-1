var ctx = document.getElementById('myChart').getContext('2d');
var ctx1 = document.getElementById('myPieChart').getContext('2d');
var ctx2 = document.getElementById('myPieChart2').getContext('2d');
var ctx3 = document.getElementById('myPieChart3').getContext('2d');
var ctx4 = document.getElementById('myPieChart4').getContext('2d'); 
var ctx5 = document.getElementById('myPieChart5').getContext('2d');

var myChart = new Chart(ctx, {
  type: 'bar',
  data: {
      labels: ['Red', 'Blue', 'Yellow', 'Green', 'Blue', 'Yellow', 'Green', 'Purple'],
      datasets: [{
        //   label: '#Votes',
          data: [12, 19, 3, 5, 8, 3, 12, 19], /*실제 값-> y축 설정을 따로 해주지 않으면 해당 데이터 셋에서 가장 높은 값을 기준으로 y축을 잡음 */
          backgroundColor:  'rgba(255, 206, 86)' ,
          borderColor: 'rgba(255, 206, 86)' ,
          borderWidth: 1 /*바 표시선 굵기*/
      }]
  },
  /*option 부분 */
  options: {
    title:{
        display: true,
        text:'전체 유사도 스코어',
        fontSize: 15,
        padding: 15,
    },
      legend:{ display: false, /*위에 범례바 안보이게 하는 기능*/
        responsive: false, /*기본 +5 : 이거 false로 설정 안하면 cavanas에 설정한 값과 달리 화면에 꽉차는 반응형으로 만들어 짐*/
        scales: {
            yAxes: [{ /*yAxs : y축에 관련된 옵션*/
                ticks: {
                    beginAtZero: true /*0부터 표기할지 정하는 거*/
                }
            }]
        },

    },
    },
});

var myPieChart = new Chart(ctx1, {
    type: 'pie',
    data: {
        // labels: ['Red', 'Blue', 'Yellow', 'Green', 'Purple', 'Orange', 'Red', 'Blue', 'Yellow', 'Green', 'Purple'],
        datasets: [{
            // label: '#Votes',
            data: [66,14,20], /*실제 값-> y축 설정을 따로 해주지 않으면 해당 데이터 셋에서 가장 높은 값을 기준으로 y축을 잡음 */
            backgroundColor:  ['rgba(255, 99, 132, 0.2)',
            'rgba(54, 162, 235, 0.2)' ,
            'rgba(255, 206, 86, 0.2)' ,
        ] , /*rbga로도 가능*/
            borderColor:  ['rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)' ,
            'rgba(255, 206, 86, 1)' ,
        ] ,
            borderWidth: 1 /*바 표시선 굵기*/
        }],
         options: {
        //     responsive: false,
             maintainAspectRatio: false
         },
    },
 });
var myPieChart2 = new Chart(ctx2, {
    type: 'pie',
    data: {
        // labels: ['Red', 'Blue', 'Yellow', 'Green', 'Purple', 'Orange', 'Red', 'Blue', 'Yellow', 'Green', 'Purple'],
        datasets: [{
            // label: '#Votes',
            data: [60,30,10], /*실제 값-> y축 설정을 따로 해주지 않으면 해당 데이터 셋에서 가장 높은 값을 기준으로 y축을 잡음 */
            backgroundColor:  ['rgba(255, 99, 132, 0.2)',
            'rgba(54, 162, 235, 0.2)' ,
            'rgba(255, 206, 86, 0.2)' ,
        ] , /*rbga로도 가능*/
            borderColor: ['rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)' ,
            'rgba(255, 206, 86, 1)' ,
        ] ,
            borderWidth: 1 /*바 표시선 굵기*/
        }],
    },
  });

var myPieChart3 = new Chart(ctx3, {
    type: 'pie',
    data: {
        // labels: ['Red', 'Blue', 'Yellow', 'Green', 'Purple', 'Orange', 'Red', 'Blue', 'Yellow', 'Green', 'Purple'],
        datasets: [{
            // label: '#Votes',
            data: [25,20,55], /*실제 값-> y축 설정을 따로 해주지 않으면 해당 데이터 셋에서 가장 높은 값을 기준으로 y축을 잡음 */
            backgroundColor:  ['rgba(255, 99, 132, 0.2)',
            'rgba(54, 162, 235, 0.2)' ,
            'rgba(255, 206, 86, 0.2)' ,
        ] , /*rbga로도 가능*/
            borderColor: ['rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)' ,
            'rgba(255, 206, 86, 1)' ,
        ] ,
            borderWidth: 1 /*바 표시선 굵기*/
        }],
    },
  });

  var myPieChart4 = new Chart(ctx4, {
    type: 'pie',
    data: {
        // labels: ['Red', 'Blue', 'Yellow', 'Green', 'Purple', 'Orange', 'Red', 'Blue', 'Yellow', 'Green', 'Purple'],
        datasets: [{
            // label: '#Votes',
            data: [20,30,50], /*실제 값-> y축 설정을 따로 해주지 않으면 해당 데이터 셋에서 가장 높은 값을 기준으로 y축을 잡음 */
            backgroundColor:  ['rgba(255, 99, 132, 0.2)',
            'rgba(54, 162, 235, 0.2)' ,
            'rgba(255, 206, 86, 0.2)' ,
        ] , /*rbga로도 가능*/
            borderColor: ['rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)' ,
            'rgba(255, 206, 86, 1)' ,
        ] ,
            borderWidth: 1 /*바 표시선 굵기*/
        }],
    },
  });

var myPieChart5 = new Chart(ctx5, {
    type: 'pie',
    data: {
        labels: ['bbh', 'cg', '상수'],
        datasets: [{
            // labels: ['bbh', 'cg', '상수'],
            data: [10,10,80], /*실제 값-> y축 설정을 따로 해주지 않으면 해당 데이터 셋에서 가장 높은 값을 기준으로 y축을 잡음 */
            backgroundColor:  ['rgba(255, 99, 132, 0.2)',
            'rgba(54, 162, 235, 0.2)' ,
            'rgba(255, 206, 86, 0.2)' ,
        ] , /*rbga로도 가능*/
            borderColor: ['rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)' ,
            'rgba(255, 206, 86, 1)' ,
        ],
            borderWidth: 1 /*바 표시선 굵기*/
        }],
    },
  });