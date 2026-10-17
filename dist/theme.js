'use strict';
// Apply the saved preference before styles render to avoid a light flash.
(() => {
 const key='simpleflow-theme';
 const system=window.matchMedia('(prefers-color-scheme: dark)');
 const valid=value=>['light','dark','system'].includes(value)?value:'light';
 let preference='light';
 try{preference=valid(localStorage.getItem(key));}catch{/* Storage may be unavailable. */}
 function apply(){
  const theme=preference==='system'?(system.matches?'dark':'light'):preference;
  document.documentElement.dataset.theme=theme;
  document.documentElement.dataset.themePreference=preference;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content',theme==='dark'?'#111b19':'#f4f6f4');
  const select=document.getElementById('theme-select');
  if(select)select.value=preference;
 }
 window.SimpleFlowTheme={setPreference(value){
  preference=valid(value);
  try{localStorage.setItem(key,preference);}catch{/* Keep the selection for this visit. */}
  apply();
 }};
 system.addEventListener('change',()=>{if(preference==='system')apply();});
 window.addEventListener('storage',event=>{
  if(event.key===key||event.key===null){preference=valid(event.newValue);apply();}
 });
 apply();
})();
