
document.addEventListener("DOMContentLoaded", function(){
  let collection = document.getElementsByClassName("SignatureEditorTarget");
  for (let counter=0;counter<collection.length;counter++){
    let element = collection[counter];
    let ilabel = "Item";
    try{
      ilabel = element.attributes.item_label.value;
    } catch(e){
      console.log(e);
    }
    let editor = new JSONEditor(document.getElementById(`${element.id}_inner_wrapper`), {
      theme: 'html',
      iconlib: 'fontawesome5',
      disable_array_add: true,
      disable_array_reorder: true,
      disable_array_delete: true,
      disable_edit_json:true,
      disable_properties:true,
      no_additional_properties:true,
      form_name_root:"",
      startval: JSON.parse(element.value),
      schema: {
        "type": "array",
        "options": {
          "compact": true,
        },
        "format": "table",
        "items": {
          "title": ilabel,
          "type": "string",
          "format": "text"
        }
      }
    });
    element.style.display = "none";
    let handler = function (ev){
      let errors = editor.validate();
      if (errors.length){
        ev.preventDefault();
      } else {
        element.value = editor.getValue();
      }
    };
    element.form.addEventListener("submit", handler, false);

  }
})
