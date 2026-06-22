import axios from 'axios';
async function test() {
  const response = await axios.get(`https://otx.alienvault.com/api/v1/indicators/hostname/campusvirtual.uap.edu.ar/url_list?limit=10`);
  console.log(response.data.url_list);
}
test();
