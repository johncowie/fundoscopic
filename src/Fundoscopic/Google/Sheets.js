/* FFI file for Sheets.purs
  Need functions for
    - creating authClient (or sheets client) with token
        - needs client ID, client secret, redirect_uri for constructor?
        - also needs token
    - querying sheets api
      - args (auth, error callback, success callback, spreadsheetId, range)

*/

const {google} = require('googleapis');

// _auth :: String -> String -> String -> String -> Auth
exports._auth = function(clientId) {
  return function(clientSecret) {
    return function(redirectUrl) {
      return function(accessToken) {
        const oAuth2Client = new google.auth.OAuth2(clientId, clientSecret, redirectUrl);
        oAuth2Client.setCredentials(accessToken)
        return oAuth2Client;
      }
    }
  }
}

exports._sheetValues = function(auth) {
  return function(spreadsheetId) {
    return function(range) {
      return function(onError, onSuccess) {
        const sheets = google.sheets({version: 'v4', auth});
        sheets.spreadsheets.values.get({
          spreadsheetId: spreadheetId,
          range: range
        }, (err, res) => {
          if(err) {
            onError(err);
            return;
          } else {
            onSuccess(res.data.values);
            return;
          }
        })

        return function (cancelError, onCancelerError, onCancelerSuccess) {
          onCancelerSuccess();
        };
      }
    }
  }
}

/*
function listMajors(auth) {
  const sheets = google.sheets({version: 'v4', auth});
  sheets.spreadsheets.values.get({
    spreadsheetId: '1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms',
    range: 'Class Data!A2:E',
  }, (err, res) => {
    if (err) return console.log('The API returned an error: ' + err);
    const rows = res.data.values;
    if (rows.length) {
      console.log('Name, Major:');
      // Print columns A and E, which correspond to indices 0 and 4.
      rows.map((row) => {
        console.log(`${row[0]}, ${row[4]}`);
      });
    } else {
      console.log('No data found.');
    }
  });
}
*/
