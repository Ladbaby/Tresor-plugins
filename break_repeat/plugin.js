const json = require('tresor/json.v1');
const encoding = require('tresor/encoding.v1');
const reminder = 'You have repeated the exact same message three times in a row. You appear to be stuck in a loop. Stop repeating yourself and take a different, concrete next step (or finish if the task is already done).';
function detect(payload) {
  if ('contents' in payload) return 'gemini';
  if ('input' in payload) return 'openai_responses';
  if (Array.isArray(payload.messages)) return payload.messages.some(m => m && typeof m.content === 'string') ? 'openai' : 'anthropic';
  return null;
}
function text(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content.filter(c => c && typeof c.text === 'string').map(c => c.text).join('');
}
function sorted(value) {
  if (!value || typeof value !== 'object' || value instanceof json.NumberToken) return value;
  if (Array.isArray(value)) return value.map(sorted);
  const out = {}; for (const key of Object.keys(value).sort()) Object.defineProperty(out,key,{value:sorted(value[key]),enumerable:true}); return out;
}
function scalar(value) { return value == null ? '' : typeof value === 'string' ? value : json.stringifyLossless(sorted(value)); }
function tool(name,args) { return {tool:scalar(name),args:scalar(args)}; }
function fingerprint(pieces) { return json.stringifyLossless(sorted(pieces)); }
function turns(payload,format) {
  const out=[];
  if (format==='gemini') {
    if (!Array.isArray(payload.contents)) return out;
    for (const m of payload.contents) if (m && m.role==='model') {
      const pieces=[]; if (Array.isArray(m.parts)) for (const p of m.parts) if(p){ if(typeof p.text==='string')pieces.push(p.text); if(p.functionCall)pieces.push(tool(p.functionCall.name,p.functionCall.args)); }
      out.push(fingerprint(pieces.length ? pieces : null));
    }
  } else if (format==='openai_responses') {
    if (!Array.isArray(payload.input))return out;
    for(const m of payload.input)if(m){
      if(m.type==='reasoning') { const pieces=Array.isArray(m.summary)?m.summary.filter(s=>s&&typeof s.text==='string').map(s=>s.text):[];out.push(fingerprint(pieces.length?pieces:null)); }
      else if(m.role==='assistant')out.push(fingerprint([text(m.content)]));
      else if(['function_call','tool_call','custom_tool_call'].includes(m.type))out.push(fingerprint([tool(m.name,m.type==='custom_tool_call'?m.input:m.arguments)]));
    }
  } else {
    if(!Array.isArray(payload.messages))return out;
    for(const m of payload.messages)if(m&&m.role==='assistant') {
      const pieces=[text(m.content)];
      if(Array.isArray(m.tool_calls))for(const call of m.tool_calls)if(call&&call.function)pieces.push(tool(call.function.name,call.function.arguments));
      if(Array.isArray(m.content))for(const b of m.content)if(b){if(b.type==='tool_use')pieces.push(tool(b.name,b.input));else if(b.type==='thinking')pieces.push({thinking:b.thinking});else if(b.type==='redacted_thinking')pieces.push({redacted_thinking:b.data});}
      out.push(fingerprint(pieces));
    }
  }
  return out;
}
function request({body,context}) {
  let format=context.formats.current;
  let payload;try {payload=json.parseLossless(encoding.decode(body));}catch(_){return;}
  if(!payload||typeof payload!=='object'||Array.isArray(payload))return;
  format=format===null||format===undefined?detect(payload):format;
  if(!['openai','anthropic','openai_responses','gemini'].includes(format))return;
  const last=turns(payload,format).slice(-3);if(last.length!==3||last[0]!==last[1]||last[1]!==last[2])return;
  if(format==='gemini')payload.contents.push({role:'user',parts:[{text:reminder}]});
  else if(format==='openai_responses')payload.input.push({role:'user',content:reminder});
  else if(format==='openai')payload.messages.push({role:'user',content:reminder});
  else {
    const block={type:'text',text:reminder},tail=payload.messages[payload.messages.length-1];
    if(tail&&tail.role==='user'){if(Array.isArray(tail.content))tail.content.push(block);else tail.content=typeof tail.content==='string'?[{type:'text',text:tail.content},block]:[block];}
    else payload.messages.push({role:'user',content:[block]});
  }
  return {body:encoding.encode(json.stringifyLossless(payload))};
}
module.exports={request};
