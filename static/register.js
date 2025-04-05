$(document).ready(function () {
  // 监听角色选择
  $('#role').on('change', function () {
    // 获取选中的值
    const selectedValue = $(this).val();

    // 检查是否选择了 "admin"
    if (selectedValue === 'admin') {
      // 弹出警告
      alert('You cannot select "admin".');

      // 将值改回 "user"
      $(this).val('user');
    }
  });

  // 验证邮箱格式
  $('#email').on('change', function () {
    const email = $(this).val();
    const reg = /^[A-Za-z0-9]+([_\.][A-Za-z0-9]+)*@([A-Za-z0-9\-]+\.)+[A-Za-z]{2,6}$/;

    if (!reg.test(email)) {
      $('#emailinfo').html('Please enter correct E-mail format like example@quiz.com');
      $('#emailinfo').css('color', 'red');
    } else {
      $('#emailinfo').html('');
    }
  });

  // 处理注册按钮点击事件
  $('#register').on('click', function() {
    const formData = new FormData();
    // Add all required fields
    formData.append('userid', $('#userid').val());
    formData.append('password', $('#password').val());
    formData.append('repassword', $('#repassword').val());  // Added repassword
    formData.append('email', $('#email').val());
    formData.append('role', $('#role').val());

    $.ajax({
        url: '/register_spqce',
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function(response) {
            if (response.status === 'success') {
                // Fixed undefined nickname reference
                alert(`Welcome, ${$('#userid').val()}! \n You can now login!`);
                window.location.href = '/otp';
            } else {
                alert(response.message);
            }
        },
        error: function(xhr) {
            const res = xhr.responseJSON || { message: 'Server error' };
            alert(res.message);
        }
    });
});
  // 返回登录页面
  $('#back').on('click', function () {
    window.location.href = '/login';
  });
});