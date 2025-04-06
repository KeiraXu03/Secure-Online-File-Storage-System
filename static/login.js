$(document).ready(function () {
  console.log("submit login request")
  // Unified form submission handler
  $('#find').on('click', function(e) {
      window.location.href = '/findpassword_page';
  });


  $('#login').on('click', function(e) {
      e.preventDefault();
      console.log("submit login request")
      const username = $('#username').val().trim();
      const password = $('#password').val().trim();
      const rememberMe = $('#rememberMe').is(':checked');

      // Validation
      if (!username || !password) {
          alert('Please fill in all fields');
          return;
      }

      // Handle remember me functionality
      if (rememberMe) {
          localStorage.setItem('username', username);
      } else {
          localStorage.removeItem('username');
      }

      // Never store password in localStorage
      const formData = new FormData();
      formData.append('username', username);
      formData.append('password', password);

      $.ajax({
          url: '/login_check',  // Corrected endpoint
          method: 'POST',
          data: formData,
          processData: false,
          contentType: false,
          success: function(response) {
              if (response.status === 'success') {
                  // Store JWT token securely
                  localStorage.setItem('access_token', response.access_token);
                  
                  // Role-based routing
                  switch(response.user.role) {
                      case 'admin':
                          window.location.href = '/admin_dashboard';
                          break;
                      case 'user':
                          sessionStorage.setItem('current_user', JSON.stringify(response.user));
                          window.location.href = '/index';
                          break;
                      default:
                          window.location.href = '/';
                  }
              } else {
                  alert(response.message);
              }
          },
          error: function(xhr) {
              const errorMsg = xhr.responseJSON?.message || 'Authentication failed';
              alert(errorMsg);
              console.error('Login Error:', xhr.responseJSON);
          }
      });
  });

  // Initialize remembered username
  const rememberedUser = localStorage.getItem('username');
  if (rememberedUser) {
      $('#username').val(rememberedUser);
  }
});