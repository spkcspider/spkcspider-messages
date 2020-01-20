
document.addEventListener("DOMContentLoaded", function(){
  let collection = document.getElementsByClassName("SignatureEditorTarget");
  for (let counter=0;counter<collection.length;counter++){
    let element = collection[counter];
    let ilabel = "Item";
    try{
      ilabel = element.dataset.item_label;
    } catch(e){
      console.log(e);
    }
    let editor = new JSONEditor(document.getElementById(`${element.id}_inner_wrapper`), {
      theme: 'html',
      iconlib: 'fontawesome5',
      disable_array_add: true,
      disable_array_reorder: true,
      disable_array_delete: true,
      disable_collapse: true,
      disable_edit_json:true,
      disable_properties:true,
      no_additional_properties:true,
      form_name_root:"",
      startval: JSON.parse(element.value),
      schema: {
        "type": "array",
        "options": {
          "compact": true,
          "inputAttributes": {
            "style": "width:100%"
          }
        },
        "items": {
          "title": ilabel,
          "type": "object",
          "properties": {
            "hash": {
              "type": "string",
              "readonly": true,
              "options": {
                "inputAttributes": {
                  "form": "dump_form"
                }
              }
            },
            "signature": {
              "type": "string",
              "format": "textarea",
              "options": {
                "inputAttributes": {
                  "form": "_dump_form"
                }
              }
            }
          }
        }
      }
    });
    element.style.display = "none";
    let handler = function (ev){
      let errors = editor.validate();
      if (errors.length){
        ev.preventDefault();
      } else {
        element.value = JSON.stringify(editor.getValue());
      }
    };
    element.form.addEventListener("submit", handler, false);

  }
})
