import logo from './logo.svg';
import './App.css';
import init, {initThreadPool, greet, proofGen, init_panic_hook, sum_of_squares} from "./pkg/halo2_examples.js";
import {useEffect} from 'react'
import React from 'react'

function App() {
  useEffect(() => {
    const wrapper = async () => {
      await init()
      await init_panic_hook()
      console.log("init panic hook done")
      await initThreadPool(navigator.hardwareConcurrency)
      console.log("init thread pool done")
      greet("WebAssembly")
      const res = sum_of_squares([1,2])
      console.log("sum of squares res", res)
      proofGen("hi")
    }
    wrapper()
  }, [])

  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Edit <code>src/App.js</code> and save to reload.
        </p>
        <p>
          {React.version}
        </p>
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn React
        </a>
      </header>
    </div>
  );
}

export default App;
