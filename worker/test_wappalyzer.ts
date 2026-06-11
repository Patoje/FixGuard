import Wappalyzer from 'wappalyzer-core';
import fs from 'fs';

async function run() {
  console.log(Object.keys(Wappalyzer));
}
run().catch(console.error);
