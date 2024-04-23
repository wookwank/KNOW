

/* --------------------------------- MAIN ---------------------------------- */
$(document).ready(function () {

    // jQuery selectors
    input_lang = $('#input-language');
    output_lang = $('#ouput-language');
    text_font = $('#text-font');

    frame7 = $(".frame7 input[type='text']");
    
});



/* ---------------------------- EVENT HANDLERS ----------------------------- */

function changeLanguage(new_lang, label_to_change) {
    if (label_to_change == "in") {
        input_lang.text(new_lang);
    } else {
        output_lang.text(new_lang);
    }
    
}

function changeFont(new_font) {
    text_font.text(new_font); 
    frame7.css("font-family", new_font);
}

function copyToClipboard(box_to_copy, box_type) {
    var input;
    // Select the text field
    if (box_type == 'input') {
        input = document.getElementById(box_to_copy)
        input = input.value;
    } else {
        input = document.getElementById(box_to_copy);
        input = input.innerHTML
        
    }
    
    navigator.clipboard.writeText(input);
    // Copy the text inside the text field
    
}