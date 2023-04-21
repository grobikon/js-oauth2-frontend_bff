// Отличие данной реализации от предыдущей - здесь используется паттерн BFF (Backend For Frontend)
// Поэтому вместо PKCE можем использовать обычный Authorization Code


// Во многих фреймфорках или библиотеках - методы для работы с OAuth2 уже готовые и не нужно будет их писать вручную
// В этом проекте мы все делаем вручную, чтобы вы лучше поняли весь алгоритм действий

// константы для использования во всем файле js
const CLIENT_ID = "todoapp-client"; // название должен совпадать c клиентом из KeyCloak
const SCOPE = "openid"; // какие данные хотите получить помимо access token (refresh token, id token, email и пр.) - можно через пробел указывать неск значений
const RESPONSE_TYPE_CODE = "code"; // для получения authorization code


// !! в каждой версии KeyCloak могут меняться URI - поэтому нужно сверяться с документацией
const KEYCLOAK_URI = "https://localhost:8443/realms/todoapp-realm/protocol/openid-connect"; // общий URI KeyCloak
const CLIENT_ROOT_URL = "https://localhost:8080"; // куда auth server будет отправлять auth code

const BFF_URI = "https://localhost:8902/bff"

// сохранение значений в память (сами токены не сохраняем, а только вспомогательные временные данные)
var accessToken = ""; // значение сбросится, если обновить веб страницу
var refreshTokenCookieExists = ""; // для получения нового access token без повторной авторизации в окне

// ключи для сохранения в localStorage
const USE_REFRESH_KEY = "USE_RT"; //
const STATE_KEY = "ST";

// вызывается при обновлении страницы
function initPage() {

    // для корректной работы и сохранения куков
    $.ajaxSetup({
        crossDomain: true, // чтобы куки сохранялись для домена, независимо от порта
        xhrFields: {
            withCredentials: true // отправлять куки в запросах на BFF
        }
    });

    if (!checkAuthCode()) { // если текущий запрос - это не ответ от auth server с новым code (через redirect uri)

        // флаг true или false (не значение токена), был ли ранее сохранен кук с Refresh Token
        // чтобы сэкономить время и не делать лишние запросы в BFF и KeyCloak и не обрабатывать ошибку
        // само значение токена сохраняется в куке и отправляется на сервер автоматически
        // флаг можено сохранять в localStorage, т.к. это не sensitive information
        refreshTokenCookieExists = localStorage.getItem(USE_REFRESH_KEY);

        if (refreshTokenCookieExists) {
            exchangeRefreshToAccessToken(); // запрашиваем новый Access Token с помощью сохраненного ранее Refresh Token (в куке браузера)
        } else {
            initAccessToken(); // никакой из других вариантов не запустился - значит запускаем полный цикл получения токенов с вводом логин-пароль
        }

    }

}


// запускаем цикл действий для grant type = PKCE (Proof Key for Code Exchange), который хорошо подходит для JS приложений в браузере
// https://www.rfc-editor.org/rfc/rfc7636
function initAccessToken() {
    // нужен только для первого запроса (авторизация), чтобы клиент убедился, что ответ от AuthServer (после авторизации) пришел именно на его нужный запрос
    // защита от CSRF атак
    var state = generateState(30);
    // console.log("state = " + state)
    localStorage.setItem(STATE_KEY, state);

    // запрашиваем auth code (вводим логин-пароль)
    requestAuthCode(state);

}


// проверяем, если в текущем запросе есть параметры ответа от auth server - значит это ответ с новым auth code
function checkAuthCode() {
    var urlParams = new URLSearchParams(window.location.search);

    console.log(urlParams);

    var authCode = urlParams.get('code'),
        state = urlParams.get('state'),
        error = urlParams.get('error'),
        errorDescription = urlParams.get('error_description');

    // если такого параметра нет
    if (!authCode) {
        return false;
    }

    // чтобы больше одного раза не исп этот параметр для страницы - мы его зануляем в истории запроса
    urlParams.set('code', '');

    // если пользователь обновит страницу, то браузер повторно отправит параметр code (и все остальные)
    // поэтому нам нужно заменить историю, и тогда code занулится
    history.replaceState(null, null, "?"+urlParams.toString());

    sendCodeToBFF(state, authCode) // получаем новые токены

    return true;
}


// зачем нужен state - чтобы на втором шаге будем сравнивать его со значением от AuthServer
// тем самым убедимся, что ответ пришел именно на наш запрос
function generateState(length) {

    // генерим случайные символы из англ алфавита
    var state = "";
    var alphaNumericCharacters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var alphaNumericCharactersLength = alphaNumericCharacters.length;
    for (var i = 0; i < length; i++) {
        state += alphaNumericCharacters.charAt(Math.floor(Math.random() * alphaNumericCharactersLength));
    }

    return state;
}


// запрос в auth server на получение auth code (который потом будем менять на access token и другие токены)
// для BFF можно применять granttype = authorization code (вместо PKCE), т.к. токены теперь не будут храниться в браузере
// поэтому параметры codeVerifier и codeChallenge не нужны
function requestAuthCode(state) {

    // в каждой версии KeyCloak может изменяться URL - поэтому нужно сверяться с документацией
    var authUrl = KEYCLOAK_URI + "/auth"; // здесь не исп BFF, а обращаемся напрямую

    authUrl += "?response_type=" + RESPONSE_TYPE_CODE; // указываем auth server, что хотим получить auth code
    authUrl += "&client_id=" + CLIENT_ID; // берем из auth server
    authUrl += "&state=" + state; // auth server сохранит это значение себе и отправит в след. запросе (вместе с access token) и клиент сможет убедиться, что ответ пришел именно на его запрос
    authUrl += "&scope=" + SCOPE; // какие данные хотите получить от auth server, помимо access token
    authUrl += "&redirect_uri=" + CLIENT_ROOT_URL; // куда auth server будет отправлять ответ

    window.open(authUrl, '_self'); // открываем в этом же окне (self) окно авторизации KeyCloak
}


// отправляем auth code в BFF, чтобы он получил все токены и сохранил их в куках
function sendCodeToBFF(stateFromAuthServer, authCode) { // idea может показывать, что функция нидге не используется, но это не так, просто он не может определить вызов из другого window

    // console.log(authCode);
    var originalState = localStorage.getItem(STATE_KEY);

    // убеждаемся, что это ответ именно на наш запрос, который отправляли ранее (для авторизации на auth server)
    if (stateFromAuthServer === originalState) {

        localStorage.removeItem(STATE_KEY);

        // отправляем auth code в BFF, чтобы он получил все токены и сохранил их в куках
        $.ajax({
            type: "POST",
            beforeSend: function (request) {
                request.setRequestHeader("Content-type", "application/json; charset=UTF-8");
            },
            url: BFF_URI + "/token",
            data: authCode, // передаем только код, остальные параметры будут заполняться на самом BFF
            success: bffTokenResponse // (callback) какой метод вызывать после успешного выполнения запроса
        });
    } else {
        initAccessToken(); // если ошибка - заново отправляем для ввода логин-пароль
    }
}

// успешный ответ от BFF, значит токены сохранены в куках
function bffTokenResponse(data, status, jqXHR) {

    // флаг, что в куках есть refresh token и его можно обменивать потом на новые access token
    localStorage.setItem(USE_REFRESH_KEY, "true");

    // получаем данные с API Resrouce Server
    getDataFromResourceServer();
}


// получить данные из Resource Server не напрямую, а через BFF, который прикрепит токены из куков и перенаправит запросы в Resource Server
// браузер отправит в запрос куки с токенами автоматически
function getDataFromResourceServer() {
    $.ajax({
        type: "GET", // тип запроса (обязательно должен быть get)
        url: BFF_URI + "/data", // адрес, куда отправляем запрос
        success: resourceServerResponse, // метод для выполнения, если запрос сработает успешно (callback)
        error: resourceServerError, // если запрос завершился ошибкой, вызываем другую функцию
        dataType: "text" // в каком формате ожидаем ответ от auth server (в нашем случае это обычный текст - для упрощения, но чаще всего это JSON)
    });
}

// обработка "успеха" от resource server (callback)
function resourceServerResponse(data, status, jqXHR) { // эти параметры передаются автоматически

    // каким образом отображать данные на странице - уже зависит от требований и технологий
    document.getElementById("userdata").innerHTML = data;
    console.log("resource server data = " + data);

}


// обработка ошибки от resource server (callback)
function resourceServerError(request, status, error) {

    try {

        // сам json
        var json = JSON.parse(request.responseText); // JSON.parse преобразовывает из текста в объект JSON

        // можно получить из json любое значение
        var errorType = json["type"];

        console.log(errorType);

        // пытаемся сначала получить refresh token из localStorage
        refreshTokenCookieExists = localStorage.getItem(USE_REFRESH_KEY);

        // если есть кук refresh token
        if (refreshTokenCookieExists) {
            // получаем новый access token с помощью него (т.е.не запускаем полный цикл PKCE, где пользователю нужно вводить логин-пароль)
            exchangeRefreshToAccessToken();

        } else { // если нет кука refresh token - запускаем полный цикл PKCE с вводом логина-пароля
            initAccessToken(); // минус этого решения - нужно будет заново вводить логин-пароль
        }
    } catch (exception) {
        console.trace();
    }

}

// получение нового access token, с помощью BFF и кука с текущим Refresh Token
// в ответе от BFF - новые токены сохранятся в куках и будут использоваться для будущих запросов
function exchangeRefreshToAccessToken() {

    console.log("new access token initiated");

    $.ajax({
        type: "GET",
        url: BFF_URI + "/newaccesstoken",
        success: bffTokenResponse, // (callback) какой метод вызывать после выполнения запроса (туда будет передан результат)
        error: exchangeRefreshError
    });
}

// в случае ошибки при обмене RT на AT - просто заново просим пользователя авторизоваться, чтобы получить новые значения
function exchangeRefreshError(request, status, error) {
    logout(); // выход из системы
}


// выйти из системы - удалить все токены и сессии в KeyCloak
function logout() {

    // обнуление
    localStorage.removeItem(USE_REFRESH_KEY);
    localStorage.removeItem(STATE_KEY);

    accessToken = "";
    refreshTokenCookieExists = "";

    console.log("logout");

    // Вызываем запрос в BFF, который обнулит все сессии в KeyCloak и занулит все куки в браузере
    // Никакие параметры не передаем, т.к. требуемый для выхода ID Token считается на сервере из кука
    // Остальные параметры сохранены на самом сервере
    $.ajax({
        type: "GET",
        url: BFF_URI + "/logout",
        success: logoutRedirect
    });
}

function logoutRedirect(request, status, error) {
    // после выполнения logout - при попытке перейти на главную страницу - отобразится окно логина-пароля, т.к. у нас нет access token, чтобы выполнять запрос в resource server
    window.location.href = "/";

}
