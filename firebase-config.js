window.FIREBASE_CONFIG = {
  apiKey: "AIzaSyCtz6MiAPW5I1BDNqJXMe-q8CgOrsEfC10",
  authDomain: "healingpath-51637.firebaseapp.com",
  databaseURL: "https://healingpath-51637-default-rtdb.europe-west1.firebasedatabase.app",
  projectId: "healingpath-51637",
  storageBucket: "healingpath-51637.firebasestorage.app",
  messagingSenderId: "247914857779",
  appId: "1:247914857779:web:1c0e49c02d3ce6f109aa46",
  measurementId: "G-J9RBTGLVV2"
};
if (typeof firebase !== 'undefined' && !firebase.apps.length) {
  firebase.initializeApp(window.FIREBASE_CONFIG);
  firebase.auth().signInAnonymously().catch(err => console.error("خطأ تسجيل الدخول:", err));
}