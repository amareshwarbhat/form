export class MainController {
  constructor($timeout, webDevTec, toastr, $http) {
    'ngInject';

    this.awesomeThings = [];

    this.classAnimation = '';
    this.creationDate = 1488868104263;
    this.toastr = toastr;
    this.activate($timeout, webDevTec);

    this.messages = [];
    var vm = this;
    this.getMessages($http, vm);

  }

  activate($timeout, webDevTec) {
    this.getWebDevTec(webDevTec);
    $timeout(() => {
      this.classAnimation = 'rubberBand';
    }, 4000);
  }

  getWebDevTec(webDevTec) {
    this.awesomeThings = webDevTec.getTec();

    angular.forEach(this.awesomeThings, (awesomeThing) => {
      awesomeThing.rank = Math.random();
    });
  }

  showToastr() {
    this.toastr.info('Fork <a href="https://github.com/Swiip/generator-gulp-angular" target="_blank"><b>generator-gulp-angular</b></a>');
    this.classAnimation = '';
  }


  getMessages($http, vm) {

    $http.get('http://localhost:5000/users').then(function (result) {
      console.log('result'); console.log(result);
      vm.messages = result.data;
    });
  }

  postMessage() {
    this.$http.post('http://localhost:5000/users', { msg: this.message });
  }

}
