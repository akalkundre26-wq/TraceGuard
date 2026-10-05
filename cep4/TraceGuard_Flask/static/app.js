document.querySelectorAll('.choices input').forEach(x=>x.addEventListener('change',()=>{const q=x.closest('.question');q.style.borderColor='#9edce6'}));
