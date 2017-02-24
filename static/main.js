$(function() {
  
  $('#dropzone').on('dragover', function() {
    $(this).addClass('hover');
  });
  
  $('#dropzone').on('dragleave', function() {
    $(this).removeClass('hover');
  });
  
  $('#dropzone input').on('change', function(e) {
    var file = this.files[0];

    $('#dropzone').removeClass('hover');

    
    $('#dropzone').addClass('dropped');
    $('#dropzone img').remove();
    
      var reader = new FileReader(file);

      reader.readAsBinaryString(file);

      console.log(file);
      
      reader.onload = function(e) {
        var data = e.target.result;

        console.log(data);
        
        $.post("/file", {data: data}, function(data){
          document.write(data)
        })
      };

      var ext = file.name.split('.').pop();
      
      $('#dropzone div').html(ext);
  });
});