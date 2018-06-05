import document from "document";

import * as simpleActivity from "./simple/activity";
import * as simpleClock from "./simple/clock";
import * as simpleHRM from "./simple/hrm";
import * as simpleSettings from "./simple/device-settings";
import * as messaging from "messaging";
import { battery } from "power";
import Weather from '../common/weather/device';

let background = document.getElementById("background");
let dividers = document.getElementsByClassName("divider");
let txtTime = document.getElementById("txtTime");
let txtDate = document.getElementById("txtDate");
let txtWeather = document.getElementById("txtWeather");
let txtBattery = document.getElementById("txtBattery");
let txtHRM = document.getElementById("txtHRM");
let iconHRM = document.getElementById("iconHRM");
let imgHRM = iconHRM.getElementById("icon");
let statsCycle = document.getElementById("stats-cycle");
let statsCycleItems = statsCycle.getElementsByClassName("cycle-item");

let weather = new Weather();

const GRANULARITY = "minutes";

txtWeather.text = "...";
txtBattery.text = "0%";

weather.setProvider("yahoo"); 
weather.setApiKey("");
weather.setMaximumAge(30 * 60 * 1000); // 30 Minutes
weather.setFeelsLike(true);

weather.onsuccess = (data) => {
  console.log("Weather is " + JSON.stringify(data));
  txtWeather.text = data.location.substring(0,9).toUpperCase() + " " + data.temperatureC + "°C";
}

weather.onerror = (error) => {
  console.log("Weather error " + error);
  txtWeather.text = error.substring(0,12).toUpperCase();
}

messaging.peerSocket.onopen = () => {
  console.log("App Socket Open, Weather Fetch");
  weather.fetch();
};

messaging.peerSocket.close = () => {
  console.log("App Socket Closed");
};

/* --------- CLOCK ---------- */
function clockCallback(data) {
  txtTime.text = data.time;
  txtDate.text = data.date;

  txtBattery.text = battery.chargeLevel + "%";
  
  weather.fetch();    
}
simpleClock.initialize(GRANULARITY, "longDate", clockCallback);

/* ------- ACTIVITY --------- */
function activityCallback(data) {
  statsCycleItems.forEach((item, index) => {
    let img = item.firstChild;
    let txt = img.nextSibling;
    txt.text = data[Object.keys(data)[index]].pretty;
    // Reposition the activity icon to the left of the variable length text
    img.x = txt.getBBox().x - txt.parent.getBBox().x - img.width - 7;
  });
}
simpleActivity.initialize(GRANULARITY, activityCallback);

/* -------- HRM ------------- */
function hrmCallback(data) {
  txtHRM.text = `${data.bpm}`;
  if (data.zone === "out-of-range") {
    imgHRM.href = "images/heart_open.png";
  } else {
    imgHRM.href = "images/heart_solid.png";
  }
  if (data.bpm !== "--") {
    iconHRM.animate("highlight");
  }
}
simpleHRM.initialize(hrmCallback);

/* -------- SETTINGS -------- */
function settingsCallback(data) {
  if (!data) {
    return;
  }
  if (data.colorBackground) {
    background.style.fill = data.colorBackground;
  }
  if (data.colorDividers) {
    dividers.forEach(item => {
      item.style.fill = data.colorDividers;
    });
  }
  if (data.colorTime) {
    txtTime.style.fill = data.colorTime;
  }
  if (data.colorDate) {
    txtDate.style.fill = data.colorDate;
  }
  if (data.colorActivity) {
    statsCycleItems.forEach((item, index) => {
      let img = item.firstChild;
      let txt = img.nextSibling;
      img.style.fill = data.colorActivity;
      txt.style.fill = data.colorActivity;
    });
  }
  if (data.colorHRM) {
    txtHRM.style.fill = data.colorHRM;
  }
  if (data.colorImgHRM) {
    imgHRM.style.fill = data.colorImgHRM;
  }
  if (data.colorWeather) {
    txtWeather.style.fill = data.colorWeather;
  }
  if (data.colorBattery) {
    txtBattery.style.fill = data.colorBattery;    
  }
}
simpleSettings.initialize(settingsCallback);
