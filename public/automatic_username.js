(function($) {

  var usernameInput = $("#user_username");
  var firstNameInput = $("#user_first_name");
  var lastNameInput = $("#user_last_name");
  var usingCustomUsername = hasValue(usernameInput);

  // Activate script only on pages that have the username input
  if (usernameInput.size() === 0) return;

  usernameInput.on("change", function() {
    usingCustomUsername = true;
  });

  firstNameInput.on("change", autoFillUsername);
  lastNameInput.on("change", autoFillUsername);

  function autoFillUsername() {
    // If user has touched the username input and its not empty skip autofill
    if (usingCustomUsername && hasValue(usernameInput)) return;

    // Autofill only from full name
    if (!hasValue(firstNameInput) || !hasValue(lastNameInput)) return;

    usernameInput.val(
      slugify(firstNameInput.val()) + "." + slugify(lastNameInput.val())
    );
  }

  function hasValue(input) {
    return !!s.trim($(input).val());
  }

  function slugify(str) {
    // Use underscore.string slugify to convert ä -> a etc. and then remove any
    // other special chars
    return s.slugify(str).replace(/[^a-z]/g, "")
  }

}(jQuery))
