const cookieModel = document.getElementsByClassName("cookie-consent-model")
const cancelCookieBtn = document.getElementById("cancelBtn")
const acceptCookieBtn = document.getElementById("acceptBtn")


acceptCookieBtn.addEventListener("click", function (){
   
    cookieModel.classList.remove("active")
    localStorage.setItem("cookieAccepted", "yes")
})
cancelCookieBtn.addEventListener("click", function(){
    cookieModel.classList.remove("active")
    alert("You Cannot Access This Page")
     location.reload() 
})
setTimeout(function (){
    const cookieAccepted = localStorage.getItem("cookieAccepted")
    if (cookieAccepted != "yes"){
        cookieModel.classList.add("active")
    }
}, 2000); 
